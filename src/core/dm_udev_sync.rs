// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::result::DmResult;

pub trait UdevSyncAction {
    fn begin(_udev_flags: u32) -> DmResult<UdevSync>;
    fn end(self, _uevent_generated: bool) -> DmResult<()>;
    fn cancel(self);
    fn cookie(&self) -> u32;
    fn is_active(&self) -> bool;
}

#[cfg(not(target_os = "android"))]
pub mod sync_semaphore {
    #[cfg(target_env = "musl")]
    use libc::{
        c_int,
        c_ushort,
        ipc_perm,
        key_t,
        sembuf,
        semctl as libc_semctl,
        semget as libc_semget,
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
    #[cfg(not(target_env = "musl"))]
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
        core::{dm_ioctl as dmi, errors},
        result::{DmError, DmResult},
    };

    use super::UdevSyncAction;

    #[cfg(target_env = "musl")]
    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct seminfo {
        pub semmap: ::std::os::raw::c_int,
        pub semmni: ::std::os::raw::c_int,
        pub semmns: ::std::os::raw::c_int,
        pub semmnu: ::std::os::raw::c_int,
        pub semmsl: ::std::os::raw::c_int,
        pub semopm: ::std::os::raw::c_int,
        pub semume: ::std::os::raw::c_int,
        pub semusz: ::std::os::raw::c_int,
        pub semvmx: ::std::os::raw::c_int,
        pub semaem: ::std::os::raw::c_int,
    }

    #[cfg(target_env = "musl")]
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct semid_ds {
        pub sem_perm: ipc_perm,
        pub sem_otime: ::std::os::raw::c_long,
        pub __sem_otime_high: ::std::os::raw::c_ulong,
        pub sem_ctime: ::std::os::raw::c_long,
        pub __sem_ctime_high: ::std::os::raw::c_ulong,
        pub sem_nsems: ::std::os::raw::c_ulong,
        pub __glibc_reserved3: ::std::os::raw::c_ulong,
        pub __glibc_reserved4: ::std::os::raw::c_ulong,
    }

    #[repr(C)]
    union semun<'a> {
        val: c_int,
        buf: &'a semid_ds,
        array: &'a c_ushort,
        __buf: &'a seminfo,
    }

    // Missing libc SysV IPC constants from /usr/include/linux/sem.h
    const GETVAL: i32 = 12;
    const SETVAL: i32 = 16;
    const SEM_INFO: i32 = 19;

    // Mode for cookie semaphore creation
    const COOKIE_MODE: i32 = 0o600;

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
        let cookie_pair = retry(NoDelay.take(4), gen_cookie);
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

    #[derive(Debug)]
    pub struct UdevSync {
        cookie: u32,
        semid: i32,
    }

    impl UdevSyncAction for UdevSync {
        fn begin(udev_flags: u32) -> DmResult<Self> {
            if (udev_flags & dmi::DM_UDEV_PRIMARY_SOURCE_FLAG) == 0 {
                return Ok(UdevSync {
                    cookie: 0,
                    semid: -1,
                });
            }
            let (base_cookie, semid) = notify_sem_create()?;
            debug!("Generated cookie key {}", base_cookie);
            let cookie =
                (udev_flags << dmi::DM_UDEV_FLAGS_SHIFT) | (base_cookie & !dmi::DM_UDEV_FLAGS_MASK);
            debug!(
                "Created UdevSync {{ cookie: {}, semid: {} }}",
                cookie, semid
            );
            if let Err(err) = notify_sem_inc(cookie, semid) {
                if let Err(err2) = notify_sem_destroy(cookie, semid) {
                    error!("Failed to clean up udev notification semaphore: {}", err2);
                }
                return Err(err);
            }
            Ok(UdevSync { cookie, semid })
        }

        fn cookie(&self) -> u32 {
            self.cookie
        }

        fn end(self, uevent_generated: bool) -> DmResult<()> {
            if !self.is_active() {
                return Ok(());
            }
            if !uevent_generated {
                if let Err(err) = notify_sem_dec(self.cookie, self.semid) {
                    error!("Failed to clear notification semaphore state: {}", err);
                    if let Err(err2) = notify_sem_destroy(self.cookie, self.semid) {
                        error!("Failed to clean up notification semaphore: {}", err2);
                    }
                    return Err(err);
                }
            }
            debug!("Waiting on {:?}", self);
            notify_sem_wait(self.cookie, self.semid)?;
            debug!("Destroying {:?}", self);
            if let Err(err) = notify_sem_destroy(self.cookie, self.semid) {
                error!("Failed to clean up notification semaphore: {}", err);
            }
            Ok(())
        }

        fn cancel(self) {
            if !self.is_active() {
                return;
            }
            debug!("Canceling {:?}", self);
            if let Err(err) = notify_sem_destroy(self.cookie, self.semid) {
                error!("Failed to clean up notification semaphore: {}", err);
            }
        }

        fn is_active(&self) -> bool {
            self.cookie != 0 && self.semid != -1
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::core::dm_flags::DmUdevFlags;

        // "DMRS"
        const IPC_TEST_KEY: i32 = 0x444d5253;

        #[test]
        fn test_semget_invalid_nsems() {
            assert!(semget(0, -1, 0).is_err());
        }

        #[test]
        fn test_semget_create_destroy() {
            match semget(IPC_TEST_KEY, 1, IPC_CREAT | IPC_EXCL) {
                Ok(semid) => {
                    assert!(semctl(semid, 0, IPC_RMID, None).is_ok());
                }
                Err(err) => {
                    panic!("Failed to create semaphore: {}", err);
                }
            }
        }

        #[test]
        fn test_notify_sem_create_destroy() {
            match notify_sem_create() {
                Ok((cookie, semid)) => {
                    assert!(notify_sem_destroy(cookie, semid).is_ok());
                }
                Err(_) => panic!("Failed to create semaphore"),
            }
        }

        #[test]
        fn test_udevsync_non_primary_source() {
            let sync = UdevSync::begin(DmUdevFlags::empty().bits()).unwrap();
            assert!(sync.cookie == 0);
            assert!(sync.semid == -1);
            assert!(sync.end(false).is_ok());
        }

        #[test]
        fn test_udevsync_non_primary_source_cancel() {
            let sync = UdevSync::begin(DmUdevFlags::empty().bits()).unwrap();
            assert!(sync.cookie == 0);
            assert!(sync.semid == -1);
            sync.cancel();
        }

        #[test]
        fn test_udevsync_primary_source_end() {
            let sync = UdevSync::begin(DmUdevFlags::DM_UDEV_PRIMARY_SOURCE_FLAG.bits()).unwrap();
            assert!((sync.cookie & !dmi::DM_UDEV_FLAGS_MASK) != 0);
            assert!(sync.semid >= 0);
            assert!(notify_sem_dec(sync.cookie, sync.semid).is_ok());
            assert!(sync.end(true).is_ok());
        }

        #[test]
        fn test_udevsync_primary_source_cancel() {
            let sync = UdevSync::begin(DmUdevFlags::DM_UDEV_PRIMARY_SOURCE_FLAG.bits()).unwrap();
            assert!((sync.cookie & !dmi::DM_UDEV_FLAGS_MASK) != 0);
            assert!(sync.semid >= 0);
            sync.cancel();
        }

        #[test]
        fn test_udevsync_primary_source_end_no_uevent() {
            let sync = UdevSync::begin(DmUdevFlags::DM_UDEV_PRIMARY_SOURCE_FLAG.bits()).unwrap();
            assert!((sync.cookie & !dmi::DM_UDEV_FLAGS_MASK) != 0);
            assert!(sync.semid >= 0);
            assert!(sync.end(false).is_ok());
        }
    }
}
#[cfg(target_os = "android")]
pub mod sync_noop {
    use super::UdevSyncAction;
    use crate::result::DmResult;

    #[derive(Debug)]
    pub struct UdevSync {
        cookie: u32,
        semid: i32,
    }

    impl UdevSyncAction for UdevSync {
        fn begin(_udev_flags: u32) -> DmResult<Self> {
            debug!("Created noop UdevSync {{ cookie: {}, semid: {} }}", 0, -1);
            Ok(UdevSync {
                cookie: 0,
                semid: -1,
            })
        }

        fn cookie(&self) -> u32 {
            self.cookie
        }

        fn end(self, _uevent_generated: bool) -> DmResult<()> {
            debug!("Destroying noop {:?}", self);
            Ok(())
        }

        fn cancel(self) {
            debug!("Canceling noop {:?}", self);
        }

        fn is_active(&self) -> bool {
            self.cookie != 0 && self.semid != -1
        }
    }
}

#[cfg(target_os = "android")]
pub use self::sync_noop::UdevSync;
#[cfg(not(target_os = "android"))]
pub use self::sync_semaphore::UdevSync;
