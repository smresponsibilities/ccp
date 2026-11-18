//! Single-instance lock for the background daemon.
//!
//! * Unix: a real advisory `flock` on `daemon.lock` (released by the kernel when the
//!   process dies, however it dies, so there are no stale locks and no PID-reuse
//!   guessing). The file also holds the daemon's PID for `ccp stop`.
//! * Windows: an exclusive open with a restricted share mode.
//!
//! Both retry briefly, because a concurrent `ccp status` / `ccp start` check holds the
//! lock for a few microseconds and must not make a starting daemon think it lost.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

const ACQUIRE_ATTEMPTS: u32 = 10;
const ACQUIRE_RETRY_DELAY: Duration = Duration::from_millis(30);

/// Holds the lock for as long as it lives.
pub struct SingleInstanceLock {
    _file: File,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    path: PathBuf,
}

impl SingleInstanceLock {
    pub fn acquire(lock_path: &Path) -> Result<Self, String> {
        acquire(lock_path)
    }
}

// On Windows the file can be deleted once the handle closes. On Unix it must NOT be:
// unlinking a lock file another process is about to open lets two daemons each lock a
// different inode.
#[cfg(target_os = "windows")]
impl Drop for SingleInstanceLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn open_exclusive(lock_path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    // share_mode(1) grants FILE_SHARE_READ but denies FILE_SHARE_WRITE.
    // Any second writer fails with ERROR_SHARING_VIOLATION (32), while readers can read the PID!
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .share_mode(1)
        .open(lock_path)
}

#[cfg(target_os = "windows")]
pub fn acquire(lock_path: &Path) -> Result<SingleInstanceLock, String> {
    if let Some(parent) = lock_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    for attempt in 0..ACQUIRE_ATTEMPTS {
        match open_exclusive(lock_path) {
            Ok(mut file) => {
                let pid = std::process::id();
                let _ = writeln!(file, "{pid}");
                let _ = file.flush();
                return Ok(SingleInstanceLock {
                    _file: file,
                    path: lock_path.to_path_buf(),
                });
            }
            Err(e)
                if e.raw_os_error() == Some(32)
                    || e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                if attempt + 1 < ACQUIRE_ATTEMPTS {
                    std::thread::sleep(ACQUIRE_RETRY_DELAY);
                }
            }
            Err(e) => return Err(format!("Failed to acquire instance lock: {e}")),
        }
    }
    Err("Daemon is already running (exclusive file lock held).".to_string())
}

#[cfg(target_os = "windows")]
pub fn is_daemon_running(lock_path: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;

    if !lock_path.exists() {
        return false;
    }

    // Attempt to open with write access and share_mode(3) (FILE_SHARE_READ | FILE_SHARE_WRITE).
    // If the daemon holds share_mode(1), write access is denied with ERROR_SHARING_VIOLATION (32).
    match std::fs::OpenOptions::new()
        .write(true)
        .share_mode(3)
        .open(lock_path)
    {
        Ok(_) => false,
        Err(e) => e.raw_os_error() == Some(32) || e.kind() == std::io::ErrorKind::PermissionDenied,
    }
}

// ---------------------------------------------------------------------------
// Unix (Linux, macOS, ...)
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
pub fn acquire(lock_path: &Path) -> Result<SingleInstanceLock, String> {
    use std::fs::TryLockError;

    if let Some(parent) = lock_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // No truncate on open: truncating before we hold the lock would wipe the PID of the
    // daemon that is actually running.
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|e| format!("Failed to open instance lock: {e}"))?;

    for attempt in 0..ACQUIRE_ATTEMPTS {
        match file.try_lock() {
            Ok(()) => {
                let _ = file.set_len(0);
                let _ = writeln!(file, "{}", std::process::id());
                let _ = file.flush();
                return Ok(SingleInstanceLock {
                    _file: file,
                    path: lock_path.to_path_buf(),
                });
            }
            Err(TryLockError::WouldBlock) => {
                if attempt + 1 < ACQUIRE_ATTEMPTS {
                    std::thread::sleep(ACQUIRE_RETRY_DELAY);
                }
            }
            Err(TryLockError::Error(e)) => {
                return Err(format!("Failed to acquire instance lock: {e}"));
            }
        }
    }
    Err("Daemon is already running (exclusive file lock held).".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn is_daemon_running(lock_path: &Path) -> bool {
    use std::fs::TryLockError;

    let Ok(file) = File::open(lock_path) else {
        return false;
    };
    match file.try_lock_shared() {
        // Nobody holds the exclusive lock -> no daemon (release our probe lock again).
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(TryLockError::WouldBlock) => true,
        Err(TryLockError::Error(_)) => false,
    }
}

/// PID recorded in the lock file (only meaningful while [`is_daemon_running`]).
pub fn read_lock_pid(lock_path: &Path) -> Option<u32> {
    std::fs::read_to_string(lock_path)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ccp_lock_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_single_instance_lock_lifecycle() {
        let dir = tmp("lifecycle");
        let lock_file = dir.join("test_daemon.lock");

        assert!(!is_daemon_running(&lock_file));

        let lock1 = acquire(&lock_file);
        assert!(lock1.is_ok(), "First acquire should succeed");
        assert!(is_daemon_running(&lock_file), "Lock should now be active");

        let lock2 = acquire(&lock_file);
        assert!(
            lock2.is_err(),
            "Second acquire should fail while lock1 is held"
        );

        drop(lock1);
        assert!(!is_daemon_running(&lock_file));

        let lock3 = acquire(&lock_file);
        assert!(lock3.is_ok());
        drop(lock3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pid_is_recorded_and_readable_while_held() {
        let dir = tmp("pid");
        let lock_file = dir.join("daemon.lock");
        let lock = acquire(&lock_file).unwrap();
        assert_eq!(read_lock_pid(&lock_file), Some(std::process::id()));
        drop(lock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_leftover_lock_file_does_not_look_like_a_running_daemon() {
        // Simulates a crashed daemon: file with a PID in it, but no process holds the lock.
        let dir = tmp("stale");
        let lock_file = dir.join("daemon.lock");
        std::fs::write(&lock_file, "1\n").unwrap(); // PID 1 is alive, but irrelevant
        assert!(!is_daemon_running(&lock_file));
        assert!(acquire(&lock_file).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn status_checks_do_not_make_a_starting_daemon_lose() {
        // Hammer is_daemon_running from another thread while acquiring.
        let dir = tmp("race");
        let lock_file = dir.join("daemon.lock");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (stop2, path2) = (stop.clone(), lock_file.clone());
        let hammer = std::thread::spawn(move || {
            while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = is_daemon_running(&path2);
            }
        });
        for _ in 0..50 {
            let lock = acquire(&lock_file).expect("acquire must not lose to a status probe");
            drop(lock);
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        hammer.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
