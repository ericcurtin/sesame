//! Filesystem primitives that make daemonless operation safe:
//! cross-process locking, atomic replacement, and private permissions.
//!
//! With no daemon to serialise access, the only coordination between two
//! `sesame` processes is the filesystem, so these functions carry the weight
//! that a server's event loop would otherwise carry.

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::{
    error::{Error, IoContext, Result, fill_random},
    item::hex,
};

/// How long to wait for another process to release a wallet lock.
///
/// Every critical section is one short read-modify-write, so waiting longer
/// than this means a process is wedged.
pub(crate) const LOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// An advisory lock on a wallet, released when dropped.
///
/// The lock lives on a dedicated sidecar file, not the wallet itself, because
/// saves atomically *replace* the wallet file: a lock on the old inode would
/// protect nothing once the rename lands. The sidecar is never deleted for the
/// same reason (deleting it would let two processes lock different inodes).
#[derive(Debug)]
pub(crate) struct FileLock {
    file: File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Closing the handle releases the lock regardless; unlocking
        // explicitly just does it a moment sooner.
        let _ = self.file.unlock();
    }
}

/// Path of the lock file that guards the wallet at `wallet`.
pub(crate) fn lock_path(wallet: &Path) -> PathBuf {
    let mut name = wallet.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// Take a shared (read) or exclusive (write) lock, waiting up to `timeout`.
pub(crate) fn acquire(wallet: &Path, exclusive: bool, timeout: Duration) -> Result<FileLock> {
    let path = lock_path(wallet);
    let file = open_lock_file(&path).context(|| format!("open lock file {}", path.display()))?;

    let deadline = Instant::now() + timeout;
    let mut delay = Duration::from_millis(1);
    loop {
        let attempt = if exclusive {
            file.try_lock()
        } else {
            file.try_lock_shared()
        };
        match attempt {
            Ok(()) => return Ok(FileLock { file }),
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(Error::LockTimeout(path));
                }
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(50));
            }
            Err(TryLockError::Error(e)) => {
                return Err(Error::io(format!("lock {}", path.display()), e));
            }
        }
    }
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    // Read+write: Windows needs one of them for LockFileEx, and shared locks
    // want a readable handle on some platforms.
    opts.read(true).write(true).create(true).truncate(false);
    restrict_to_owner(&mut opts);
    opts.open(path)
}

/// Read a whole file, refusing anything over `max` bytes.
pub(crate) fn read_file(path: &Path, max: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::WalletNotFound(path.to_owned()),
        _ => Error::io(format!("open {}", path.display()), e),
    })?;
    let mut buf = Vec::new();
    // Read one byte past the limit so an oversized file is noticed, not truncated.
    file.take(max as u64 + 1)
        .read_to_end(&mut buf)
        .context(|| format!("read {}", path.display()))?;
    if buf.len() > max {
        return Err(Error::Corrupt("file is too large to be a wallet"));
    }
    Ok(buf)
}

/// Replace `path` with `data` so that a reader (or a crash) sees either the old
/// contents or the new contents in full, never a mixture.
///
/// The data is written to a sibling temporary file, flushed to stable storage,
/// and renamed over the destination.
///
/// If `path` is a symlink (say, into a synced folder) the file it points to is
/// replaced and the link is left alone; renaming over the link itself would
/// quietly turn it into a regular file.
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let resolved;
    let path = match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            resolved =
                fs::canonicalize(path).context(|| format!("resolve symlink {}", path.display()))?;
            resolved.as_path()
        }
        _ => path,
    };
    let dir = parent_dir(path);
    let mut suffix = [0u8; 6];
    fill_random(&mut suffix)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{file_name}.{}.tmp", hex(&suffix)));

    let result = (|| -> Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        restrict_to_owner(&mut opts);
        let mut f = opts
            .open(&tmp)
            .context(|| format!("create {}", tmp.display()))?;
        f.write_all(data)
            .context(|| format!("write {}", tmp.display()))?;
        f.sync_all().context(|| format!("sync {}", tmp.display()))?;
        drop(f);
        rename_replace(&tmp, path)
            .context(|| format!("replace {} with {}", path.display(), tmp.display()))?;
        // Persist the rename itself. A failure here is not worth failing the
        // save for: the data is already in place.
        let _ = sync_dir(dir);
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Create the directory that holds wallets, private to the current user.
///
/// A directory that already exists is left exactly as it is: it's the user's,
/// and wallet contents are encrypted regardless.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).context(|| format!("create directory {}", parent.display()))?;
    }
    match private_dir_builder().create(dir) {
        Ok(()) => Ok(()),
        // Lost a race with another sesame creating it.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
        Err(e) => Err(Error::io(format!("create directory {}", dir.display()), e)),
    }
}

/// A builder for the wallet directory: mode 0700 on unix. On Windows the new
/// directory inherits its parent's ACL (see [`restrict_to_owner`]).
#[cfg(unix)]
fn private_dir_builder() -> fs::DirBuilder {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
}

#[cfg(not(unix))]
fn private_dir_builder() -> fs::DirBuilder {
    fs::DirBuilder::new()
}

/// Make files created with `opts` readable only by their owner (0600) on unix.
///
/// On Windows new files inherit the ACL of the containing directory, which
/// under the user profile is already limited to the user, SYSTEM and
/// Administrators.
#[allow(unused_variables)]
fn restrict_to_owner(opts: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
}

#[cfg(not(windows))]
fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

/// On Windows a rename can fail transiently when an indexer or antivirus
/// scanner has the destination open. Retry briefly before giving up.
#[cfg(windows)]
fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    let mut attempt = 0;
    loop {
        match fs::rename(from, to) {
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied && attempt < 20 => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(25));
            }
            other => return other,
        }
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    // Windows offers no way to flush a directory; NTFS journals the rename.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_path_appends_suffix() {
        assert_eq!(
            lock_path(Path::new("/x/y/default.sesame")),
            Path::new("/x/y/default.sesame.lock")
        );
    }

    #[test]
    fn write_atomic_creates_then_replaces_and_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.sesame");
        write_atomic(&p, b"one").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"one");
        write_atomic(&p, b"two-longer").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two-longer");
        write_atomic(&p, b"x").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"x");

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(leftovers, ["w.sesame"]);
    }

    #[test]
    fn write_atomic_failure_cleans_up_and_preserves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.sesame");
        write_atomic(&p, b"original").unwrap();

        // Make the destination a non-empty directory so the final rename fails
        // after the temp file was written.
        let blocked = dir.path().join("blocked.sesame");
        fs::create_dir(&blocked).unwrap();
        fs::write(blocked.join("child"), b"x").unwrap();
        assert!(write_atomic(&blocked, b"data").is_err());

        assert_eq!(fs::read(&p).unwrap(), b"original");
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            names.iter().all(|n| !n.ends_with(".tmp")),
            "temp file left behind: {names:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn files_and_new_directories_are_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let d = root.path().join("nested").join("sesame");
        ensure_private_dir(&d).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&d), 0o700);

        let f = d.join("w.sesame");
        write_atomic(&f, b"x").unwrap();
        assert_eq!(mode(&f), 0o600);

        let _lock = acquire(&f, true, LOCK_TIMEOUT).unwrap();
        assert_eq!(mode(&lock_path(&f)), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_follows_a_symlink_instead_of_replacing_it() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let synced = root.path().join("synced");
        let home = root.path().join("home");
        fs::create_dir(&synced).unwrap();
        fs::create_dir(&home).unwrap();
        let real = synced.join("w.sesame");
        let link = home.join("w.sesame");
        fs::write(&real, b"old").unwrap();
        symlink(&real, &link).unwrap();

        write_atomic(&link, b"new").unwrap();

        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink must survive a save"
        );
        assert_eq!(fs::read(&real).unwrap(), b"new", "target gets the new data");
        assert_eq!(fs::read(&link).unwrap(), b"new");
        // The temp file lives next to the real file and is gone again.
        assert_eq!(fs::read_dir(&synced).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&home).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_reports_a_dangling_symlink() {
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("w.sesame");
        std::os::unix::fs::symlink(root.path().join("missing"), &link).unwrap();
        assert!(write_atomic(&link, b"x").is_err());
    }

    #[test]
    fn existing_directory_is_left_alone() {
        let root = tempfile::tempdir().unwrap();
        ensure_private_dir(root.path()).unwrap();
        ensure_private_dir(root.path()).unwrap();
    }

    #[test]
    fn exclusive_locks_exclude_and_release_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let w = dir.path().join("w.sesame");

        let first = acquire(&w, true, LOCK_TIMEOUT).unwrap();
        let blocked = acquire(&w, true, Duration::from_millis(50));
        assert!(matches!(blocked, Err(Error::LockTimeout(_))));
        let blocked_reader = acquire(&w, false, Duration::from_millis(50));
        assert!(matches!(blocked_reader, Err(Error::LockTimeout(_))));

        drop(first);
        acquire(&w, true, Duration::from_millis(50)).expect("lock is free after drop");
    }

    #[test]
    fn shared_locks_coexist_but_block_writers() {
        let dir = tempfile::tempdir().unwrap();
        let w = dir.path().join("w.sesame");

        let r1 = acquire(&w, false, LOCK_TIMEOUT).unwrap();
        let r2 = acquire(&w, false, Duration::from_millis(50)).expect("readers share");
        assert!(matches!(
            acquire(&w, true, Duration::from_millis(50)),
            Err(Error::LockTimeout(_))
        ));
        drop((r1, r2));
        acquire(&w, true, Duration::from_millis(50)).unwrap();
    }

    #[test]
    fn read_file_distinguishes_missing_from_oversized() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.sesame");
        assert!(matches!(read_file(&p, 10), Err(Error::WalletNotFound(_))));
        fs::write(&p, [0u8; 11]).unwrap();
        assert!(matches!(read_file(&p, 10), Err(Error::Corrupt(_))));
        assert_eq!(read_file(&p, 11).unwrap().len(), 11);
    }
}
