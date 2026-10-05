//! The error type shared by the whole library.

use std::{fmt, io, path::PathBuf};

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong while working with a wallet.
///
/// Messages are written for end users and never contain secret material or
/// attribute values.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An operating-system I/O call failed.
    Io {
        /// What we were trying to do, e.g. `read /home/me/.local/share/sesame/default.sesame`.
        context: String,
        /// The underlying error.
        source: io::Error,
    },
    /// No wallet file exists at this path.
    WalletNotFound(PathBuf),
    /// A wallet file already exists at this path.
    WalletExists(PathBuf),
    /// The wallet name is not acceptable.
    InvalidWalletName {
        /// The rejected name.
        name: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// The password was wrong, or the wallet has been tampered with or corrupted.
    ///
    /// Authenticated encryption cannot distinguish these cases, by design.
    Authentication,
    /// The wallet's password was changed by another process after this handle
    /// was opened. Re-open the wallet with the new password.
    WalletRekeyed,
    /// The wallet file is structurally invalid.
    Corrupt(&'static str),
    /// The wallet file was written by a newer, incompatible version of sesame.
    UnsupportedVersion(u8),
    /// Key-derivation parameters are outside the accepted range.
    InvalidKdfParams(&'static str),
    /// The password cannot be used.
    InvalidPassword(&'static str),
    /// An item (label, attribute, ...) failed validation.
    InvalidItem(String),
    /// No item matched.
    ItemNotFound,
    /// An item-id prefix matched more than one item.
    AmbiguousId,
    /// Another process held the wallet lock for too long.
    LockTimeout(PathBuf),
    /// The operating system could not provide random bytes.
    Random(String),
    /// The wallet would exceed the maximum supported size.
    TooLarge,
    /// The key-derivation function could not allocate its working memory.
    OutOfMemory,
    /// The platform has no per-user data directory and none was supplied.
    NoDataDir,
}

impl Error {
    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { context, source } => write!(f, "failed to {context}: {source}"),
            Error::WalletNotFound(p) => write!(f, "wallet not found: {}", p.display()),
            Error::WalletExists(p) => write!(f, "wallet already exists: {}", p.display()),
            Error::InvalidWalletName { name, reason } => {
                write!(f, "invalid wallet name {name:?}: {reason}")
            }
            Error::Authentication => f.write_str("wrong password, or the wallet file is corrupted"),
            Error::WalletRekeyed => {
                f.write_str("the wallet password was changed by another process; open it again")
            }
            Error::Corrupt(why) => write!(f, "wallet file is corrupt: {why}"),
            Error::UnsupportedVersion(v) => write!(
                f,
                "wallet file format version {v} is not supported by this build of sesame"
            ),
            Error::InvalidKdfParams(why) => write!(f, "invalid key-derivation parameters: {why}"),
            Error::InvalidPassword(why) => write!(f, "invalid password: {why}"),
            Error::InvalidItem(why) => write!(f, "invalid item: {why}"),
            Error::ItemNotFound => f.write_str("no matching item"),
            Error::AmbiguousId => f.write_str("item id prefix matches more than one item"),
            Error::LockTimeout(p) => write!(
                f,
                "timed out waiting for another process to release {}",
                p.display()
            ),
            Error::Random(why) => write!(f, "could not get random bytes from the OS: {why}"),
            Error::TooLarge => f.write_str("wallet would exceed the maximum supported size"),
            Error::OutOfMemory => {
                f.write_str("not enough memory for the configured key-derivation cost")
            }
            Error::NoDataDir => f.write_str(
                "could not determine a per-user data directory; set SESAME_DIR or pass --dir",
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Attach context to `io::Result`s.
pub(crate) trait IoContext<T> {
    fn context(self, f: impl FnOnce() -> String) -> Result<T>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn context(self, f: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error::io(f(), e))
    }
}

/// Fill `buf` with OS randomness.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::Random(e.to_string()))
}
