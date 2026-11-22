use anyhow::{Context, Result};
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

pub fn desktop_data_dir() -> Result<PathBuf> {
    Ok(dirs::data_dir()
        .context("cannot locate FolderSpan Desktop data directory")?
        .join("FolderSpan"))
}

pub struct InstanceLock {
    _file: File,
}
impl InstanceLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // JVM FileChannel.tryLock uses POSIX record locks, not flock.
            let mut lock: libc::flock = unsafe { std::mem::zeroed() };
            lock.l_type = libc::F_WRLCK as _;
            lock.l_whence = libc::SEEK_SET as _;
            lock.l_start = 0;
            lock.l_len = 0;
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) } == -1 {
                return Err(std::io::Error::last_os_error())
                    .context("FolderSpan instance is already running");
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::{
                Storage::FileSystem::{
                    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
                },
                System::IO::OVERLAPPED,
            };
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            if unsafe {
                LockFileEx(
                    file.as_raw_handle(),
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    u32::MAX,
                    0x7fff_ffff,
                    &mut overlapped,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("FolderSpan instance is already running");
            }
        }
        Ok(Self { _file: file })
    }
}
