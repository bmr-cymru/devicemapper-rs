// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use libc::{
    c_int,
    c_ushort,
    key_t,
    sembuf,
    semctl as libc_semctl,
    semget as libc_semget,
    semid_ds,
    seminfo,
    semop as libc_semop,
    EEXIST,
    ENOMEM,
    ENOSPC,
    // These don't exist in the Linux libc crate
    // GETVAL, SETVAL, SEM_INFO,
    IPC_CREAT,
    IPC_EXCL,
    IPC_NOWAIT,
    IPC_RMID,
};
use rand::Rng;
use retry::{delay::NoDelay, retry, OperationResult};
use std::io;

use crate::{
    core::{dm_flags::DmUdevFlags, dm_ioctl as dmi, errors},
    result::{DmError, DmResult},
};

// Missing libc SysV IPC constants from /usr/include/linux/sem.h
const GETVAL: i32 = 12;
const SETVAL: i32 = 16;
const SEM_INFO: i32 = 19;

// Mode for cookie semaphore creation
const COOKIE_MODE: i32 = 0o600;

#[repr(C)]
union semun<'a> {
    val: c_int,
    buf: &'a semid_ds,
    array: &'a c_ushort,
    __buf: &'a seminfo,
}

fn udev_sync_error_from_os() -> DmError {
    DmError::Core(errors::Error::UdevSync(
        io::Error::last_os_error().to_string(),
    ))
}

fn semget(key: i32, nsems: i32, semflg: i32) -> Result<i32, std::io::Error> {
    let semid = unsafe { libc_semget(key as key_t, nsems as c_int, semflg as c_int) };
    match semid {
        -1 => Err(io::Error::last_os_error()),
        _ => Ok(semid),
    }
}

fn semctl_cmd_allowed(cmd: i32) -> Result<(), std::io::Error> {
    match cmd {
        IPC_RMID | GETVAL | SETVAL | SEM_INFO => Ok(()),
        _ => Err(io::Error::from(io::ErrorKind::Unsupported)),
    }
}

fn semctl(
    semid: i32,
    semnum: i32,
    cmd: i32,
    semun: Option<semun<'_>>,
) -> Result<i32, std::io::Error> {
    semctl_cmd_allowed(cmd)?;
    let r = unsafe { libc_semctl(semid as c_int, semnum as c_int, cmd as c_int, semun) };
    match r {
        -1 => Err(io::Error::last_os_error()),
        _ => Ok(r),
    }
}

fn gen_cookie() -> OperationResult<(u32, i32), std::io::Error> {
    let mut base_cookie = 0u16;
    while base_cookie == 0 {
        base_cookie = rand::thread_rng().gen::<u16>();
    }
    let cookie = dmi::DM_COOKIE_MAGIC << dmi::DM_UDEV_FLAGS_SHIFT | base_cookie as u32;
    match semget(cookie as i32, 1, COOKIE_MODE | IPC_CREAT | IPC_EXCL) {
        Ok(semid) => OperationResult::Ok((cookie, semid)),
        Err(err) => match err.raw_os_error() {
            Some(ENOMEM) => OperationResult::Err(err),
            Some(ENOSPC) => OperationResult::Err(err),
            Some(EEXIST) => OperationResult::Retry(err),
            _ => OperationResult::Err(err),
        },
    }
}

fn notify_sem_create() -> DmResult<(u32, i32)> {
    let cookie_pair = retry(NoDelay.take(4), || gen_cookie());
    if let Err(err) = cookie_pair {
        error!("Failed to generate udev notification semaphore: {}", err);
        return Err(DmError::Core(errors::Error::UdevSync(err.to_string())));
    }
    let (cookie, semid) = cookie_pair.unwrap();
    let sem_arg: semun<'_> = semun { val: 1 };
    if let Err(err) = semctl(semid, 0, SETVAL, Some(sem_arg)) {
        error!("Failed to initialize udev notification semaphore: {}", err);
        if let Err(err2) = notify_sem_destroy(cookie, semid) {
            error!("Failed to clean up udev notification semaphore: {}", err2);
        }
        return Err(DmError::Core(errors::Error::UdevSync(err.to_string())));
    }
    match semctl(semid, 0, GETVAL, None) {
        Ok(1) => Ok((cookie, semid)),
        _ => {
            error!("Initalization of udev notification semaphore returned inconsistent value.");
            Err(udev_sync_error_from_os())
        }
    }
}

fn notify_sem_destroy(cookie: u32, semid: i32) -> DmResult<()> {
    if let Err(err) = semctl(semid, 0, IPC_RMID, None) {
        error!(
            "Failed to remove udev synchronization semaphore {} for cookie {}",
            semid, cookie
        );
        return Err(DmError::Core(errors::Error::UdevSync(err.to_string())));
    };
    Ok(())
}

fn notify_sem_inc(cookie: u32, semid: i32) -> DmResult<()> {
    // DM protocol always uses the 0th semaphore in the set identified by semid
    let mut sb = sembuf {
        sem_num: 0,
        sem_op: 1,
        sem_flg: 0,
    };
    let r = unsafe { libc_semop(semid, &mut sb, 1) };
    match r {
        -1 => {
            error!(
                "Failed to increment udev synchronization semaphore {} for cookie {}",
                semid, cookie
            );
            Err(udev_sync_error_from_os())
        }
        _ => Ok(()),
    }
}

fn notify_sem_dec(cookie: u32, semid: i32) -> DmResult<()> {
    // DM protocol always uses the 0th semaphore in the set identified by semid
    let mut sb = sembuf {
        sem_num: 0,
        sem_op: -1,
        sem_flg: IPC_NOWAIT as i16,
    };
    let r = unsafe { libc_semop(semid, &mut sb, 1) };
    match r {
        -1 => {
            error!(
                "Failed to decrement udev synchronization semaphore {} for cookie {}",
                semid, cookie
            );
            Err(udev_sync_error_from_os())
        }
        _ => Ok(()),
    }
}

fn notify_sem_wait(cookie: u32, semid: i32) -> DmResult<()> {
    if let Err(err) = notify_sem_dec(cookie, semid) {
        error!(
            concat!(
                "Failed to set initial state for notification ",
                "semaphore identified by cookie value {}: {}"
            ),
            cookie, err
        );
        if let Err(err2) = notify_sem_destroy(cookie, semid) {
            error!("Failed to clean up udev notification semaphore: {}", err2);
        }
    }
    let mut sb = sembuf {
        sem_num: 0,
        sem_op: 0,
        sem_flg: 0,
    };
    let r = unsafe { libc_semop(semid, &mut sb, 1) };
    match r {
        -1 => {
            error!(
                "Failed to wait on notification semaphore {} for cookie {}",
                semid, cookie
            );
            Err(udev_sync_error_from_os())
        }
        _ => Ok(()),
    }
}

pub fn udev_sync_begin(udev_flags: DmUdevFlags) -> DmResult<(u32, i32)> {
    let (base_cookie, semid) = notify_sem_create()?;
    debug!("Generated base cookie {}", base_cookie);
    let cookie = udev_flags.to_cookie(base_cookie);
    debug!("Created cookie {} semid {}", cookie & dmi::DM_UDEV_PRIMARY_SOURCE_FLAG, semid);
    if let Err(err) = notify_sem_inc(cookie, semid) {
        if let Err(err2) = notify_sem_destroy(cookie, semid) {
            error!("Failed to clean up udev notification semaphore: {}", err2);
        }
        return Err(err);
    }
    Ok((cookie as u32, semid))
}

pub fn udev_sync_end(hdr: &dmi::Struct_dm_ioctl, cookie: u32, semid: i32) -> DmResult<()> {
    if cookie == 0 {
        return Ok(())
    }
    if (hdr.flags & dmi::DM_UEVENT_GENERATED_FLAG) == 0 {
        if let Err(err) = notify_sem_dec(cookie, semid) {
            error!("Failed to clear notification semaphore state: {}", err);
            if let Err(err2) = notify_sem_destroy(cookie, semid) {
                error!("Failed to clean up notification semaphore: {}", err2);
            }
            return Err(err);
        }
    }
    debug!("Waiting on semid {} cookie {}", semid, cookie);
    notify_sem_wait(cookie, semid)?;
    debug!("Destroying semid {} cookie {}", semid, cookie);
    if let Err(err) = notify_sem_destroy(cookie, semid) {
        error!("Failed to clean up notification semaphore: {}", err);
    }
    Ok(())
}

pub fn udev_sync_cancel(cookie: u32, semid: i32) {
    debug!("Canceling udev sync for cookie {} semid {}", cookie, semid);
    if let Err(err) = notify_sem_destroy(cookie, semid) {
        error!("Failed to clean up notification semaphore: {}", err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // "DMRS"
    const IPC_TEST_KEY: i32 = 0x444d5253;

    #[test]
    fn test_semget_invalid_nsems() {
        match semget(0, -1, 0) {
            Ok(_val) => assert!(false, "semget(2) with negative nsems should fail"),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_semget_create_destroy() {
        match semget(IPC_TEST_KEY, 1, IPC_CREAT | IPC_EXCL) {
            Ok(semid) => {
                if let Ok(_) = semctl(semid, 0, IPC_RMID, None) {
                    assert!(true)
                } else {
                    assert!(false, "Failed to destroy semaphore set")
                }
            }
            Err(err) => {
                assert!(false, "{}", err.to_string());
            }
        }
    }

    #[test]
    fn test_notify_sem_create_destroy() {
        match notify_sem_create() {
            Ok((cookie, semid)) => {
                assert!(true);
                match notify_sem_destroy(cookie, semid) {
                    Ok(_) => assert!(true),
                    Err(_) => assert!(false, "Failed to destroy semaphore"),
                }
            }
            Err(_) => assert!(false, "Failed to create semaphore"),
        }
    }
}
