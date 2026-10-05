//! The per-user directory that holds wallets, and wallet naming.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, IoContext, Result},
    kdf::KdfParams,
    wallet::Wallet,
};

/// Name of the wallet used when none is specified.
pub const DEFAULT_WALLET: &str = "default";

/// File extension of wallet files.
pub const WALLET_EXTENSION: &str = "sesame";

const MAX_NAME_LEN: usize = 64;

/// Device names Windows reserves in every directory, with or without an extension.
const WINDOWS_RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Check that `name` is a safe, portable wallet name.
///
/// Names are used verbatim as file names, so they are restricted to
/// lowercase ASCII letters, digits, `-`, `_` and `.`. That rules out path
/// traversal, and being lowercase-only means two names can never collide on
/// a case-insensitive filesystem (the macOS and Windows default). Names also
/// cannot start with `.` or `-`, end with `.`, or be a Windows device name,
/// so a wallet directory can be copied between operating systems.
pub fn validate_wallet_name(name: &str) -> Result<()> {
    let bad = |reason: &'static str| {
        Err(Error::InvalidWalletName {
            name: name.to_owned(),
            reason,
        })
    };
    if name.is_empty() {
        return bad("must not be empty");
    }
    if name.len() > MAX_NAME_LEN {
        return bad("must be at most 64 characters");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.'))
    {
        return bad("may only contain lowercase letters, digits, '-', '_' and '.'");
    }
    if name.starts_with(['.', '-']) {
        return bad("must not start with '.' or '-'");
    }
    if name.ends_with('.') {
        return bad("must not end with '.'");
    }
    let stem = name.split('.').next().unwrap_or(name);
    if WINDOWS_RESERVED.contains(&stem) {
        return bad("is a reserved device name on Windows");
    }
    Ok(())
}

/// The default wallet directory for the current user.
///
/// | Platform | Location                                 |
/// |----------|------------------------------------------|
/// | Linux    | `$XDG_DATA_HOME/sesame` (`~/.local/share/sesame`) |
/// | macOS    | `~/Library/Application Support/sesame`   |
/// | Windows  | `%LOCALAPPDATA%\sesame`                  |
///
/// Windows uses the local rather than the roaming profile so wallets are not
/// silently copied between machines by profile roaming.
pub fn default_dir() -> Result<PathBuf> {
    dirs::data_local_dir()
        .map(|d| d.join("sesame"))
        .ok_or(Error::NoDataDir)
}

/// A directory containing wallets.
#[derive(Clone, Debug)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// A store rooted at `dir`. The directory is created on first use.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Store { dir: dir.into() }
    }

    /// A store at the platform default location, see [`default_dir`].
    pub fn at_default_location() -> Result<Self> {
        Ok(Store::new(default_dir()?))
    }

    /// The directory this store lives in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file a wallet called `name` is stored in.
    pub fn wallet_path(&self, name: &str) -> Result<PathBuf> {
        validate_wallet_name(name)?;
        Ok(self.dir.join(format!("{name}.{WALLET_EXTENSION}")))
    }

    /// Whether a wallet called `name` exists.
    pub fn exists(&self, name: &str) -> Result<bool> {
        let path = self.wallet_path(name)?;
        path.try_exists()
            .context(|| format!("check {}", path.display()))
    }

    /// Names of all wallets in the directory, sorted. A missing directory
    /// simply has no wallets.
    pub fn list(&self) -> Result<Vec<String>> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::io(format!("read {}", self.dir.display()), e)),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.context(|| format!("read {}", self.dir.display()))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some(WALLET_EXTENSION) {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if validate_wallet_name(stem).is_ok() && path.is_file() {
                names.push(stem.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Create a new wallet called `name`.
    pub fn create_wallet(&self, name: &str, password: &str, kdf: KdfParams) -> Result<Wallet> {
        Wallet::create(self.wallet_path(name)?, password, kdf)
    }

    /// Unlock the wallet called `name`.
    pub fn open_wallet(&self, name: &str, password: &str) -> Result<Wallet> {
        Wallet::open(self.wallet_path(name)?, password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        for n in [
            "default",
            "work",
            "a",
            "my-wallet_2",
            "v1.2",
            "a.b.c",
            "0day",
        ] {
            validate_wallet_name(n).unwrap_or_else(|e| panic!("{n}: {e}"));
        }
        validate_wallet_name(&"a".repeat(64)).unwrap();
    }

    #[test]
    fn rejects_dangerous_or_unportable_names() {
        let long = "a".repeat(65);
        for n in [
            "",
            long.as_str(),
            "../etc/passwd",
            "..",
            ".",
            ".hidden",
            "-flag",
            "trailing.",
            "has space",
            "slash/y",
            "back\\slash",
            "colon:name",
            "Upper",
            "ünïcode",
            "nul\0byte",
            "tab\t",
            "con",
            "nul",
            "aux",
            "com1",
            "lpt9",
            "con.backup",
            "prn.x.y",
        ] {
            assert!(
                matches!(
                    validate_wallet_name(n),
                    Err(Error::InvalidWalletName { .. })
                ),
                "{n:?} should be rejected"
            );
        }
        // Looks reserved but isn't.
        validate_wallet_name("console").unwrap();
        validate_wallet_name("com10").unwrap();
    }

    #[test]
    fn wallet_path_uses_extension_inside_dir() {
        let s = Store::new("/data/sesame");
        assert_eq!(
            s.wallet_path("work").unwrap(),
            Path::new("/data/sesame/work.sesame")
        );
        assert!(s.wallet_path("../x").is_err());
    }

    #[test]
    fn list_finds_only_wallet_files() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::new(dir.path());
        assert!(s.list().unwrap().is_empty());

        let fast = KdfParams::new(8, 1, 1).unwrap();
        s.create_wallet("zeta", "pw", fast).unwrap();
        s.create_wallet("alpha", "pw", fast).unwrap();
        // Noise that must be ignored: lock files, temp files, other files,
        // directories named like wallets, and invalid names.
        fs::write(dir.path().join("notes.txt"), "x").unwrap();
        fs::write(dir.path().join(".hidden.sesame"), "x").unwrap();
        fs::write(dir.path().join("Bad Name.sesame"), "x").unwrap();
        fs::create_dir(dir.path().join("dir.sesame")).unwrap();

        assert_eq!(s.list().unwrap(), ["alpha", "zeta"]);
        assert!(s.exists("alpha").unwrap());
        assert!(!s.exists("missing").unwrap());
    }

    #[test]
    fn opening_a_missing_wallet_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::new(dir.path().join("does-not-exist-yet"));
        assert!(matches!(
            s.open_wallet("default", "pw"),
            Err(Error::WalletNotFound(_))
        ));
    }

    #[test]
    fn default_dir_ends_in_sesame() {
        if let Ok(d) = default_dir() {
            assert_eq!(d.file_name().unwrap(), "sesame");
        }
    }
}
