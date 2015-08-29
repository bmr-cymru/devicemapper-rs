// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Low-level devicemapper configuration of the running kernel.
//!
//! # Overview
//!
//! Linux's devicemapper allows the creation of block devices whose
//! storage is mapped to other block devices in useful ways, either by
//! changing the location of its data blocks, or performing some
//! operation on the data itself. This is a low-level facility that is
//! used by higher-level volume managers such as LVM2. Uses may
//! include:
//!
//! * Dividing a large block device into smaller logical volumes (dm-linear)
//! * Combining several separate block devices into a single block
//!   device with better performance and/or redundancy (dm-raid)
//! * Encrypting a block device (dm-crypt)
//! * Performing Copy-on-Write (COW) allocation of a volume's blocks
//!   enabling fast volume cloning and snapshots (dm-thin)
//! * Configuring a smaller, faster block device to act as a cache for a
//!   larger, slower one (dm-cache)
//! * Verifying the contents of a read-only volume (dm-verity)
//!
//! # Usage
//!
//! Before they can be used, DM devices must be created using
//! `DM::device_create()`, have a mapping table loaded using
//! `DM::table_load()`, and then activated with
//! `DM::device_resume()`. Once activated, they can be used as a
//! regular block device, including having other DM devices map to
//! them.
//!
//! Devices have "active" and "inactive" mapping tables. See function
//! descriptions for which table they affect.

#![feature(slice_bytes, path_ext, iter_arith)]
#![warn(missing_docs)]

extern crate libc;
extern crate nix;

#[macro_use]
extern crate bitflags;

#[allow(dead_code, non_camel_case_types)]
mod dm_ioctl;
mod util;

use std::fs::{File, PathExt};
use std::io::{Result, Error, BufReader, BufRead};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::io::ErrorKind::Other;
use std::os::unix::io::AsRawFd;
use std::mem;
use std::slice;
use std::slice::bytes::copy_memory;
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;

use nix::sys::ioctl;

use dm_ioctl as dmi;
use util::align_to;

const DM_IOCTL: u8 = 0xfd;
const DM_CTL_PATH: &'static str= "/dev/mapper/control";

const DM_VERSION_MAJOR: u32 = 4;
const DM_VERSION_MINOR: u32 = 30;
const DM_VERSION_PATCHLEVEL: u32 = 0;

const DM_IOCTL_STRUCT_LEN: usize = 312;
const DM_NAME_LEN: usize = 128;
const DM_UUID_LEN: usize = 129;

bitflags!(
    /// Flags used by devicemapper.
    flags DmFlags: dmi::__u32 {
        /// In: Device should be read-only.
        /// Out: Device is read-only.
        const DM_READONLY_FLAG             = (1 << 0),
        /// In: Device should be suspended.
        /// Out: Device is suspended.
        const DM_SUSPEND_FLAG              = (1 << 1),
        /// In: Use passed-in minor number.
        const DM_PERSISTENT_DEV_FLAG       = (1 << 3),
        /// In: STATUS command returns table info instead of status.
        const DM_STATUS_TABLE_FLAG         = (1 << 4),
        /// Out: Active table is present.
        const DM_ACTIVE_PRESENT_FLAG       = (1 << 5),
        /// Out: Inactive table is present.
        const DM_INACTIVE_PRESENT_FLAG     = (1 << 6),
        /// Out: Passed-in buffer was too small.
        const DM_BUFFER_FULL_FLAG          = (1 << 8),
        /// Obsolete.
        const DM_SKIP_BDGET_FLAG           = (1 << 9),
        /// In: Avoid freezing filesystem when suspending.
        const DM_SKIP_LOCKFS_FLAG          = (1 << 10),
        /// In: Suspend without flushing queued I/Os.
        const DM_NOFLUSH_FLAG              = (1 << 11),
        /// In: Query inactive table instead of active.
        const DM_QUERY_INACTIVE_TABLE_FLAG = (1 << 12),
        /// Out: A uevent was generated, the caller may need to wait for it.
        const DM_UEVENT_GENERATED_FLAG     = (1 << 13),
        /// In: Rename affects UUID field, not name field.
        const DM_UUID_FLAG                 = (1 << 14),
        /// In: All buffers are wiped after use. Use when handling crypto keys.
        const DM_SECURE_DATA_FLAG          = (1 << 15),
        /// Out: A message generated output data.
        const DM_DATA_OUT_FLAG             = (1 << 16),
        /// In: Do not remove in-use devices.
        /// Out: Device scheduled to be removed when closed.
        const DM_DEFERRED_REMOVE_FLAG      = (1 << 17),
        /// Out: Device is suspended internally.
        const DM_INTERNAL_SUSPEND_FLAG     = (1 << 18),
    }
);


/// Used with `DM::table_status()` to choose either return of info or
/// tables for a target. The contents of each of these strings is
/// target-specific.
#[derive(Debug, Clone, Copy)]
pub enum StatusType {
    /// Return a target's `STATUSTYPE_INFO`.
    Info,
    /// Return a target's `STATUSTYPE_TABLE`.
    Table,
}

/// A struct containing the device's major and minor numbers
///
/// Also allows conversion to/from a single 64bit value.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Device {
    /// Device major number
    pub major: u32,
    /// Device minor number
    pub minor: u8,
}

impl Device {
    /// Returns the path in `/dev` that corresponds with the device number.
    pub fn path(&self) -> Option<PathBuf> {
        let f = File::open("/proc/partitions")
            .ok().expect("Could not open /proc/partitions");

        let reader = BufReader::new(f);

        for line in reader.lines().skip(2) {
            if let Ok(line) = line {
                let spl: Vec<_> = line.split_whitespace().collect();

                if spl[0].parse::<u32>().unwrap() == self.major
                    && spl[1].parse::<u8>().unwrap() == self.minor {
                        return Some(PathBuf::from(format!("/dev/{}", spl[3])));
                    }
            }
        }
        None
    }
}

impl FromStr for Device {
    type Err = Error;
    fn from_str(s: &str) -> Result<Device> {
        match s.parse::<i64>() {
            Ok(x) => Ok(Device::from(x as u64)),
            Err(_) => {
                match Path::new(s).metadata() {
                    Ok(x) => Ok(Device::from(x.rdev())),
                    Err(x) => Err(x)
                }
            }
        }
    }
}

impl From<u64> for Device {
    fn from(val: u64) -> Device {
        Device { major: (val >> 8) as u32, minor: (val & 0xff) as u8 }
    }
}

impl From<Device> for u64 {
    fn from(dev: Device) -> u64 {
        ((dev.major << 8) ^ (dev.minor as u32 & 0xff)) as u64
    }
}


/// Major numbers used by DM.
pub fn dev_majors() -> BTreeSet<u32> {
    let mut set = BTreeSet::new();

    let f = File::open("/proc/devices")
        .ok().expect("Could not open /proc/devices");

    let reader = BufReader::new(f);

    for line in reader.lines()
        .filter_map(|x| x.ok())
        .skip_while(|x| x != "Block devices:")
        .skip(1) {
            let spl: Vec<_> = line.split_whitespace().collect();

            if spl[1] == "device-mapper" {
                set.insert(spl[0].parse::<u32>().unwrap());
            }
        }

    set
}

/// Contains information about the device.
pub struct DeviceInfo {
    hdr: dmi::Struct_dm_ioctl,
}

impl DeviceInfo {
    /// The major, minor, and patchlevel versions of devicemapper.
    pub fn version(&self) -> (u32, u32, u32) {
        (self.hdr.version[0], self.hdr.version[1], self.hdr.version[2])
    }

    /// The number of times the device is currently open.
    pub fn open_count(&self) -> i32 {
        self.hdr.open_count
    }

    /// The last event number for the device.
    pub fn event_nr(&self) -> u32 {
        self.hdr.event_nr
    }

    /// The device's major and minor device numbers, as a Device.
    pub fn device(&self) -> Device {
        self.hdr.dev.into()
    }

    /// The device's name.
    pub fn name(&self) -> String {
        let name: &[u8; DM_NAME_LEN] = unsafe { mem::transmute(&self.hdr.name) };
        let slc = slice_to_null(name).unwrap();
        String::from_utf8_lossy(slc).into_owned()
    }

    /// The device's UUID.
    pub fn uuid(&self) -> String {
        let uuid: &[u8; DM_UUID_LEN] = unsafe { mem::transmute(&self.hdr.uuid) };
        let slc = slice_to_null(uuid).unwrap();
        String::from_utf8_lossy(slc).into_owned()
    }

    /// The flags returned from the device.
    pub fn flags(&self) -> DmFlags {
        DmFlags::from_bits_truncate(self.hdr.flags)
    }
}


/// Context needed for communicating with devicemapper.
pub struct DM {
    file: File,
}

impl DM {
    /// Create a new context for communicating with DM.
    pub fn new() -> Result<DM> {
        Ok(DM {
            file: try!(File::open(DM_CTL_PATH)),
        })
    }

    fn initialize_hdr(hdr: &mut dmi::Struct_dm_ioctl, flags: DmFlags) -> () {
        hdr.version[0] = DM_VERSION_MAJOR;
        hdr.version[1] = DM_VERSION_MINOR;
        hdr.version[2] = DM_VERSION_PATCHLEVEL;

        hdr.flags = flags.bits;

        hdr.data_start = mem::size_of::<dmi::Struct_dm_ioctl>() as u32;
    }

    fn hdr_set_name(hdr: &mut dmi::Struct_dm_ioctl, name: &str) -> () {
        let name_dest: &mut [u8; DM_NAME_LEN] = unsafe { mem::transmute(&mut hdr.name) };
        copy_memory(name.as_bytes(), &mut name_dest[..]);
    }

    fn hdr_set_uuid(hdr: &mut dmi::Struct_dm_ioctl, uuid: &str) -> () {
        let uuid_dest: &mut [u8; DM_UUID_LEN] = unsafe { mem::transmute(&mut hdr.uuid) };
        copy_memory(uuid.as_bytes(), &mut uuid_dest[..]);
    }

    /// Devicemapper version information: Major, Minor, and patchlevel versions.
    pub fn version(&self) -> Result<(u32, u32, u32)> {

        let mut hdr: dmi::Struct_dm_ioctl = Default::default();
        hdr.version[0] = DM_VERSION_MAJOR;
        hdr.version[1] = DM_VERSION_MINOR;
        hdr.version[2] = DM_VERSION_PATCHLEVEL;

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_VERSION_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut hdr) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => {},
        };

        Ok((hdr.version[0], hdr.version[1], hdr.version[2]))
    }

    /// Remove all DM devices and tables. Use discouraged other than
    /// for debugging.
    pub fn remove_all(&self, flags: DmFlags) -> Result<()> {
        let mut hdr: dmi::Struct_dm_ioctl = Default::default();

        Self::initialize_hdr(&mut hdr, flags);

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_REMOVE_ALL_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut hdr) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => Ok(())
        }
    }

    /// Returns a list of tuples containing DM device names and a
    /// Device, which holds their major and minor device numbers.
    pub fn list_devices(&self, flags: DmFlags) -> Result<Vec<(String, Device)>> {
        let mut buf = [0u8; 16 * 1024];
        let mut hdr: &mut dmi::Struct_dm_ioctl = unsafe {mem::transmute(&mut buf)};

        Self::initialize_hdr(&mut hdr, flags);
        hdr.data_size = buf.len() as u32;

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_LIST_DEVICES_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut buf) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => {},
        };

        let mut devs = Vec::new();
        if (hdr.data_size - hdr.data_start as u32) != 0 {
            let mut result = &buf[hdr.data_start as usize..];

            loop {
                let device: &dmi::Struct_dm_name_list = unsafe {
                    mem::transmute(result.as_ptr())
                };

                let slc = slice_to_null(
                    &result[mem::size_of::<dmi::Struct_dm_name_list>()..])
                    .expect("Bad data from ioctl");
                let dm_name = String::from_utf8_lossy(slc).into_owned();
                devs.push((dm_name, device.dev.into()));

                if device.next == 0 { break }

                result = &result[device.next as usize..];
            }
        }

        Ok(devs)
    }

    /// Create a DM device. It starts out in a "suspended" state.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let dm = devicemapper::DM::new().unwrap();
    ///
    /// // Setting a uuid is optional
    /// let dev = dm.device_create("example-dev", None).unwrap();
    /// ```
    ///
    pub fn device_create(&self, name: &str, uuid: Option<&str>, flags: DmFlags) -> Result<Device> {
        let mut hdr: dmi::Struct_dm_ioctl = Default::default();

        Self::initialize_hdr(&mut hdr, flags);
        Self::hdr_set_name(&mut hdr, name);
        if let Some(uuid) = uuid {
            Self::hdr_set_uuid(&mut hdr, uuid);
        }

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_DEV_CREATE_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut hdr) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => { }
        };

        Ok(Device::from(hdr.dev))
    }

    /// Remove a DM device and its mapping tables.
    pub fn device_remove(&self, name: &str, flags: DmFlags) -> Result<()> {
        let mut hdr: dmi::Struct_dm_ioctl = Default::default();

        Self::initialize_hdr(&mut hdr, flags);
        Self::hdr_set_name(&mut hdr, name);

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_DEV_REMOVE_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut hdr) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => Ok(())
        }
    }

    /// Rename a DM device.
    pub fn device_rename(&self, old_name: &str, new_name: &str, flags: DmFlags) -> Result<()> {
        let mut buf = [0u8; DM_IOCTL_STRUCT_LEN + DM_NAME_LEN];
        let mut hdr: &mut dmi::Struct_dm_ioctl = unsafe {mem::transmute(&mut buf)};

        if new_name.as_bytes().len() > (DM_NAME_LEN - 1) {
            return Err(
                Error::new(Other, format!("New name {} too long", new_name)));
        }

        Self::initialize_hdr(&mut hdr, flags);
        hdr.data_size = buf.len() as u32;
        Self::hdr_set_name(&mut hdr, old_name);

        copy_memory(new_name.as_bytes(), &mut buf[DM_IOCTL_STRUCT_LEN..]);

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_DEV_RENAME_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut hdr) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => Ok(())
        }
    }

    /// Suspend a DM device. Will block until pending I/O is
    /// completed.  Additional I/O to a suspended device will be held
    /// until it is resumed.
    pub fn device_suspend(&self, name: &str, flags: DmFlags) -> Result<()> {
        let mut hdr: dmi::Struct_dm_ioctl = Default::default();

        Self::initialize_hdr(&mut hdr, flags);
        Self::hdr_set_name(&mut hdr, name);
        hdr.flags = DM_SUSPEND_FLAG.bits;

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_DEV_SUSPEND_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut hdr) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => Ok(())
        }
    }

    /// Resume a DM device. This moves a table loaded into the "inactive" slot by
    /// `table_load()` into the "active" slot.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let dm = devicemapper::DM::new().unwrap();
    ///
    /// dm.device_resume("example-dev").unwrap();
    /// ```
    ///
    pub fn device_resume(&self, name: &str, flags: DmFlags) -> Result<()> {
        let mut hdr: dmi::Struct_dm_ioctl = Default::default();

        Self::initialize_hdr(&mut hdr, flags);
        Self::hdr_set_name(&mut hdr, name);
        // DM_SUSPEND_FLAG not set = resume

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_DEV_SUSPEND_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut hdr) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => Ok(())
        }
    }

    /// Get device status for the "active" table.
    pub fn device_status(&self, name: &str, flags: DmFlags) -> Result<DeviceInfo> {
        let mut hdr: dmi::Struct_dm_ioctl = Default::default();

        Self::initialize_hdr(&mut hdr, flags);
        Self::hdr_set_name(&mut hdr, name);

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_DEV_STATUS_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut hdr) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => Ok(DeviceInfo {hdr: hdr})
        }
    }

    /// Unimplemented.
    pub fn device_wait(&self, _name: &str) -> Result<()> {
        unimplemented!()
    }

    /// Load targets for a device.
    /// `targets` is a Vec of (sector_start, sector_length, type, params).
    ///
    /// `params` are target-specific, please see [Linux kernel documentation](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/device-mapper) for more.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let dm = devicemapper::DM::new().unwrap();
    ///
    /// // Create a 16MiB device (32768 512-byte sectors) that maps to /dev/sdb1
    /// // starting 1MiB into sdb1
    /// let table = vec![(0, 32768, "linear", "/dev/sdb1 2048")];
    ///
    /// dm.table_load("example-dev", &table).unwrap();
    /// ```
    ///
    pub fn table_load(&self, name: &str, targets: &Vec<(u64, u64, &str, &str)>, flags: DmFlags) -> Result<()> {
        let mut targs = Vec::new();

        // Construct targets first, since we need to know how many & size
        // before initializing the header.
        for t in targets {
            let mut targ: dmi::Struct_dm_target_spec = Default::default();
            targ.sector_start = t.0;
            targ.length = t.1;
            targ.status = 0;

            let mut dst: &mut [u8] = unsafe {
                mem::transmute(&mut targ.target_type[..])
            };
            copy_memory(t.2.as_bytes(), &mut dst);

            let mut params = t.3.to_string();

            let pad_bytes = align_to(
                params.len() + 1usize, 8usize) - params.len();
            params.extend(vec!["\0"; pad_bytes]);

            targ.next = (mem::size_of::<dmi::Struct_dm_target_spec>()
                         + params.len()) as u32;

            targs.push((targ, params));
        }

        let mut hdr: dmi::Struct_dm_ioctl = Default::default();

        Self::initialize_hdr(&mut hdr, flags);
        Self::hdr_set_name(&mut hdr, name);

        hdr.data_start = mem::size_of::<dmi::Struct_dm_ioctl>() as u32;
        hdr.data_size = hdr.data_start + targs.iter()
            .map(|&(t, _)| t.next)
            .sum::<u32>();
        hdr.target_count = targs.len() as u32;

        // Flatten into buf
        let mut buf: Vec<u8> = Vec::with_capacity(hdr.data_size as usize);
        unsafe {
            let ptr: *mut u8 = mem::transmute(&mut hdr);
            let slc = slice::from_raw_parts(ptr, hdr.data_start as usize);
            buf.extend(slc);
        }

        for (targ, param) in targs {
            unsafe {
                let ptr: *mut u8 = mem::transmute(&targ);
                let slc = slice::from_raw_parts(
                    ptr, mem::size_of::<dmi::Struct_dm_target_spec>());
                buf.extend(slc);
            }

            buf.extend(param.as_bytes());
        }

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_TABLE_LOAD_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into_ptr(self.file.as_raw_fd(), op, buf.as_mut_ptr()) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => Ok(())
        }
    }

    /// Clear the "inactive" table for a device.
    pub fn table_clear(&self, name: &str, flags: DmFlags) -> Result<()> {
        let mut hdr: dmi::Struct_dm_ioctl = Default::default();

        Self::initialize_hdr(&mut hdr, flags);
        Self::hdr_set_name(&mut hdr, name);

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_TABLE_CLEAR_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut hdr) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => Ok(())
        }
    }

    /// Query DM for which devices are referenced by the "active"
    /// table for this device.
    pub fn table_deps(&self, dev: Device, flags: DmFlags) -> Result<Vec<Device>> {
        let mut buf = [0u8; 16 * 1024];
        let mut hdr: &mut dmi::Struct_dm_ioctl = unsafe {mem::transmute(&mut buf)};

        Self::initialize_hdr(&mut hdr, flags);
        hdr.data_size = buf.len() as u32;
        hdr.dev = dev.into();

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_TABLE_DEPS_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut buf) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => {},
        };

        // TODO: Check DM_BUFFER_FULL_FLAG for:
        // DM_DEVICE_LIST_VERSIONS, DM_DEVICE_LIST, DM_DEVICE_DEPS,
        // DM_DEVICE_STATUS, DM_DEVICE_TABLE, DM_DEVICE_WAITEVENT,
        // DM_DEVICE_TARGET_MSG

        let mut devs = Vec::new();
        if (hdr.data_size - hdr.data_start as u32) != 0 {
            let result = &buf[hdr.data_start as usize..];
            let deps: &dmi::Struct_dm_target_deps = unsafe {
                mem::transmute(result.as_ptr())
            };

            let dev_slc = unsafe {
                slice::from_raw_parts(
                    result[mem::size_of::<dmi::Struct_dm_target_deps>()..]
                        .as_ptr() as *const u64,
                    deps.count as usize)
            };

            for dev in dev_slc {
                devs.push(Device::from(*dev));
            }
        }

        Ok(devs)
    }

    /// Return the status of all targets for a device's "active"
    /// table.
    ///
    /// Returns is a Vec of (sector_start, sector_length,
    /// type, params).
    pub fn table_status(&self, name: &str, flags: DmFlags)
                        -> Result<Vec<(u64, u64, String, String)>> {
        let mut buf = [0u8; 16 * 1024];
        let mut hdr: &mut dmi::Struct_dm_ioctl = unsafe {mem::transmute(&mut buf)};

        Self::initialize_hdr(&mut hdr, flags);
        Self::hdr_set_name(&mut hdr, name);
        hdr.data_size = buf.len() as u32;

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_TABLE_STATUS_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut buf) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => {},
        };

        let mut targets = Vec::new();
        if (hdr.data_size - hdr.data_start as u32) != 0 {
            let mut result = &buf[hdr.data_start as usize..];

            for _ in 0..hdr.target_count {
                let targ: &dmi::Struct_dm_target_spec = unsafe {
                    mem::transmute(result.as_ptr())
                };

                let target_type = unsafe {
                    let cast: &[u8; 16] = mem::transmute(&targ.target_type);
                    let slc = slice_to_null(cast).expect("bad data from ioctl");
                    String::from_utf8_lossy(slc).into_owned()
                };

                let params = {
                    let slc = slice_to_null(
                        &result[mem::size_of::<dmi::Struct_dm_target_spec>()..])
                        .expect("bad data from ioctl");
                    String::from_utf8_lossy(slc).into_owned()
                };

                targets.push((targ.sector_start, targ.length, target_type, params));

                result = &result[targ.next as usize..];
            }
        }

        Ok(targets)
    }

    /// Returns a list of each loaded target with its name, and version
    /// broken into major, minor, and patchlevel.
    pub fn list_versions(&self, flags: DmFlags) -> Result<Vec<(String, u32, u32, u32)>> {
        let mut buf = [0u8; 16 * 1024];
        let mut hdr: &mut dmi::Struct_dm_ioctl = unsafe {mem::transmute(&mut buf)};

        Self::initialize_hdr(&mut hdr, flags);
        hdr.data_size = buf.len() as u32;
        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_LIST_VERSIONS_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut buf) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => {},
        };

        let mut targets = Vec::new();
        if (hdr.data_size - hdr.data_start as u32) != 0 {
            let mut result = &buf[hdr.data_start as usize..];

            loop {
                let tver: &dmi::Struct_dm_target_versions = unsafe {
                    mem::transmute(result.as_ptr())
                };

                let name_slc = slice_to_null(
                    &result[mem::size_of::<dmi::Struct_dm_target_versions>()..])
                    .expect("bad data from ioctl");
                let name = String::from_utf8_lossy(name_slc).into_owned();
                targets.push((name, tver.version[0], tver.version[1], tver.version[2]));

                if tver.next == 0 { break }

                result = &result[tver.next as usize..];
            }
        }

        Ok(targets)
    }

    /// Send a message to the target at a given sector. If sector is not needed use 0.
    /// DM-wide messages start with '@', and may return a string; targets do not.
    pub fn target_msg(&self, name: &str, sector: u64, msg: &str, flags: DmFlags) -> Result<Option<String>> {
        let mut buf = [0u8; 16 * 1024];
        let mut hdr: &mut dmi::Struct_dm_ioctl = unsafe {mem::transmute(&mut buf)};

        Self::initialize_hdr(&mut hdr, flags);
        Self::hdr_set_name(&mut hdr, name);

        hdr.data_size = hdr.data_start
            + mem::size_of::<dmi::Struct_dm_target_msg>() as u32
            + msg.as_bytes().len() as u32 + 1;

        {
            let mut data_in = &mut buf[hdr.data_start as usize..];
            let mut msg_struct: &mut dmi::Struct_dm_target_msg = unsafe {
                mem::transmute(data_in.as_ptr())
            };
            msg_struct.sector = sector;

            let mut data_in = &mut data_in[mem::size_of::<dmi::Struct_dm_target_msg>()..];
            copy_memory(msg.as_bytes(), &mut data_in);
        }

        let op = ioctl::op_read_write(DM_IOCTL, dmi::DM_TARGET_MSG_CMD as u8,
                                      mem::size_of::<dmi::Struct_dm_ioctl>());

        match unsafe { ioctl::read_into(self.file.as_raw_fd(), op, &mut hdr) } {
            Err(_) => return Err((Error::last_os_error())),
            _ => { }
        };

        match (hdr.flags & DM_DATA_OUT_FLAG.bits) > 0 {
            true => Ok(Some(String::from_utf8_lossy(
                &buf[hdr.data_start as usize..hdr.data_size as usize]).into_owned())),
            false => Ok(None)
        }
    }

    /// Unimplemented.
    pub fn device_set_geometry(&self, _flags: DmFlags) {
        unimplemented!()
    }

    /// Recursively walk DM deps to see if `dev` might be its own dependency.
    pub fn depends_on(&self, dev: Device, dm_majors: &BTreeSet<u32>) -> bool {
        if !dm_majors.contains(&dev.major) {
            return false;
        }

        if let Ok(dep_list) = self.table_deps(dev, DmFlags::empty()) {
            for d in dep_list {
                if d == dev {
                    return true;
                } else if self.depends_on(d, dm_majors) {
                    return true;
                }
            }
        }

        false
    }
}

//
// Return up to the first \0, or None
//
fn slice_to_null(slc: &[u8]) -> Option<&[u8]> {
    for (i, c) in slc.iter().enumerate() {
        if *c == b'\0' { return Some(&slc[..i]) };
    }
    None
}
