//! An unlocked wallet handle.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use zeroize::Zeroizing;

use crate::{
    error::{Error, Result, fill_random},
    format::{self, Header, MAX_FILE_LEN},
    fsutil::{self, LOCK_TIMEOUT},
    item::{Attributes, Item, NewItem, PutOutcome, Vault},
    kdf::{self, KEY_LEN, KdfParams, Key, SALT_LEN},
};

/// A wallet that has been unlocked with its password.
///
/// There is no daemon, so a `Wallet` is not a connection to anything: it is
/// the derived key plus a path. Each method is a self-contained transaction on
/// the file:
///
/// 1. take the wallet's lock (shared to read, exclusive to write),
/// 2. read and decrypt the file as it is *right now*,
/// 3. apply the operation,
/// 4. if it changed anything, encrypt with a fresh nonce and atomically
///    replace the file,
/// 5. release the lock.
///
/// Because nothing is cached between calls, any number of `Wallet`s, in any
/// number of processes, can be used concurrently without lost updates.
///
/// The slow part of unlocking, Argon2, happens once in [`Wallet::open`] /
/// [`Wallet::create`], not per call. Dropping the `Wallet` wipes the key.
pub struct Wallet {
    path: PathBuf,
    key: Key,
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("path", &self.path)
            .field("kdf", &self.kdf)
            .finish_non_exhaustive()
    }
}

/// Lock a wallet that must already exist.
///
/// Checking first means that probing a missing wallet reports
/// [`Error::WalletNotFound`] and doesn't leave a stray lock file behind. (If
/// the file vanishes after the check, reading it reports the same error.)
fn lock_existing(path: &Path, exclusive: bool) -> Result<fsutil::FileLock> {
    match path.try_exists() {
        Ok(true) => fsutil::acquire(path, exclusive, LOCK_TIMEOUT),
        Ok(false) => Err(Error::WalletNotFound(path.to_owned())),
        Err(e) => Err(Error::io(format!("check {}", path.display()), e)),
    }
}

impl Wallet {
    /// Create a new, empty wallet at `path`.
    ///
    /// Fails with [`Error::WalletExists`] rather than overwrite an existing
    /// file. The parent directory is created (private to the user) if needed.
    pub fn create(path: impl AsRef<Path>, password: &str, kdf: KdfParams) -> Result<Wallet> {
        let path = path.as_ref();

        // Derive before taking the lock so it is held only for the file work.
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        let key = kdf::derive_key(password, &salt, &kdf)?;

        if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fsutil::ensure_private_dir(dir)?;
        }
        let _lock = fsutil::acquire(path, true, LOCK_TIMEOUT)?;
        match path.try_exists() {
            Ok(false) => {}
            Ok(true) => return Err(Error::WalletExists(path.to_owned())),
            Err(e) => return Err(Error::io(format!("check {}", path.display()), e)),
        }

        let wallet = Wallet {
            path: path.to_owned(),
            key,
            salt,
            kdf,
        };
        let file = format::seal(kdf, salt, &wallet.key, &Vault::default())?;
        fsutil::write_atomic(path, &file)?;
        Ok(wallet)
    }

    /// Unlock the wallet at `path`.
    ///
    /// Returns [`Error::Authentication`] if the password is wrong.
    pub fn open(path: impl AsRef<Path>, password: &str) -> Result<Wallet> {
        let path = path.as_ref();
        let bytes = {
            let _lock = lock_existing(path, false)?;
            fsutil::read_file(path, MAX_FILE_LEN)?
        };
        let header = Header::decode(&bytes)?;
        let key = kdf::derive_key(password, &header.salt, &header.kdf)?;

        // Prove the password by decrypting once.
        format::open(bytes, &key)?;

        Ok(Wallet {
            path: path.to_owned(),
            key,
            salt: header.salt,
            kdf: header.kdf,
        })
    }

    /// Where this wallet lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The key-derivation cost this wallet is currently protected with.
    #[must_use]
    pub fn kdf_params(&self) -> KdfParams {
        self.kdf
    }

    /// Run `f` on a consistent snapshot of the wallet's contents.
    pub fn read<R>(&self, f: impl FnOnce(&Vault) -> R) -> Result<R> {
        let bytes = {
            let _lock = lock_existing(&self.path, false)?;
            fsutil::read_file(&self.path, MAX_FILE_LEN)?
        };
        // Decrypt outside the lock; the snapshot is already in memory.
        let vault = self.decrypt(bytes)?;
        Ok(f(&vault))
    }

    /// Atomically modify the wallet.
    ///
    /// The exclusive lock is held across the whole read, `f`, and write, so
    /// concurrent updates from other processes queue up instead of clobbering
    /// each other. If `f` returns an error nothing is written. If `f` makes no
    /// changes, the file is not rewritten.
    pub fn update<R>(&self, f: impl FnOnce(&mut Vault) -> Result<R>) -> Result<R> {
        let _lock = lock_existing(&self.path, true)?;
        let bytes = fsutil::read_file(&self.path, MAX_FILE_LEN)?;
        let mut vault = self.decrypt(bytes)?;

        let out = f(&mut vault)?;

        if vault.is_dirty() {
            let file = format::seal(self.kdf, self.salt, &self.key, &vault)?;
            fsutil::write_atomic(&self.path, &file)?;
        }
        Ok(out)
    }

    /// Re-encrypt the wallet under a new password (and cost parameters).
    ///
    /// A new random salt is generated. On success this handle is switched to
    /// the new key; other open handles will get [`Error::WalletRekeyed`].
    pub fn change_password(&mut self, new_password: &str, new_kdf: KdfParams) -> Result<()> {
        let mut new_salt = [0u8; SALT_LEN];
        fill_random(&mut new_salt)?;
        let new_key = kdf::derive_key(new_password, &new_salt, &new_kdf)?;

        let _lock = lock_existing(&self.path, true)?;
        let bytes = fsutil::read_file(&self.path, MAX_FILE_LEN)?;
        let vault = self.decrypt(bytes)?;

        let file = format::seal(new_kdf, new_salt, &new_key, &vault)?;
        fsutil::write_atomic(&self.path, &file)?;

        self.key = new_key;
        self.salt = new_salt;
        self.kdf = new_kdf;
        Ok(())
    }

    /// Decrypt `bytes` with this handle's key, noticing a concurrent re-key.
    fn decrypt(&self, bytes: Vec<u8>) -> Result<Vault> {
        let header = Header::decode(&bytes)?;
        if header.salt != self.salt {
            return Err(Error::WalletRekeyed);
        }
        let key: &Zeroizing<[u8; KEY_LEN]> = &self.key;
        format::open(bytes, key)
    }

    // ---- conveniences over `read` / `update` -------------------------------

    /// Every item, ordered by label.
    pub fn list(&self) -> Result<Vec<Item>> {
        self.search(&Attributes::new())
    }

    /// Items whose attributes include every pair in `query`.
    pub fn search(&self, query: &Attributes) -> Result<Vec<Item>> {
        self.read(|v| v.search(query).into_iter().cloned().collect())
    }

    /// The item with this id, or this unambiguous id prefix.
    pub fn get(&self, id_or_prefix: &str) -> Result<Item> {
        self.read(|v| v.get(id_or_prefix).cloned())?
    }

    /// Store an item. See [`Vault::put`] for the meaning of `replace`.
    pub fn put(&self, item: NewItem, replace: bool) -> Result<PutOutcome> {
        self.update(|v| v.put(item, replace))
    }

    /// Delete the item with this id or unambiguous id prefix.
    pub fn delete(&self, id_or_prefix: &str) -> Result<()> {
        self.update(|v| {
            let id = v.get(id_or_prefix)?.id.clone();
            v.remove(&id).map(|_| ())
        })
    }

    /// Delete every item matching `query`, returning how many were deleted.
    pub fn delete_matching(&self, query: &Attributes) -> Result<usize> {
        self.update(|v| Ok(v.remove_matching(query)))
    }
}
