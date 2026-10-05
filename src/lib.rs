//! # sesame
//!
//! A rootless, daemonless secret store: the job of KWallet or gnome-keyring,
//! without the service.
//!
//! * **Daemonless.** A wallet is one encrypted file. There is no background
//!   process, no D-Bus service and no socket. Every operation locks the file,
//!   decrypts it, does its work, atomically writes it back and returns. Any
//!   number of processes can use a wallet at once; the filesystem lock
//!   serialises them.
//! * **Rootless.** Everything lives in per-user directories with owner-only
//!   permissions. Nothing needs installing system-wide, and nothing ever runs
//!   with elevated privileges.
//! * **Portable.** Pure Rust with no C dependencies, built for macOS, Linux
//!   and Windows on x86-64 and aarch64. Wallet files are byte-for-byte
//!   identical across all of them, so a wallet can be copied or synced
//!   between machines.
//!
//! ## Model
//!
//! The data model follows the freedesktop Secret Service. An [`Item`] is a
//! [`Secret`] with a label and string [`Attributes`]; you find items by
//! attribute match (`service=github user=ann`), not by name.
//!
//! ## Example
//!
//! ```
//! use sesame::{Attributes, KdfParams, NewItem, Wallet};
//!
//! # let dir = tempfile::tempdir()?;
//! # let path = dir.path().join("demo.sesame");
//! # let kdf = KdfParams::new(8, 1, 1)?; // fast, for the doctest only
//! // Use `KdfParams::default()` for real wallets.
//! let wallet = Wallet::create(&path, "correct horse battery staple", kdf)?;
//!
//! wallet.put(
//!     NewItem::new("GitHub token", "ghp_exampletoken")
//!         .attribute("service", "github")
//!         .attribute("user", "ann"),
//!     true,
//! )?;
//!
//! // Later, possibly from another process:
//! let wallet = Wallet::open(&path, "correct horse battery staple")?;
//! let mut query = Attributes::new();
//! query.insert("service".into(), "github".into());
//! let found = wallet.search(&query)?;
//! assert_eq!(found[0].secret.expose(), b"ghp_exampletoken");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Security properties and limits
//!
//! Wallet contents, including labels and attributes, are encrypted with
//! XChaCha20-Poly1305 under a key derived from the password with Argon2id.
//! The whole file, header included, is authenticated. The file format is
//! specified in the `format` module's source.
//!
//! Because there is no daemon, there is also no unlocked state to protect
//! between commands, which is a real advantage over a resident keyring: a
//! locked wallet is simply a file. The price is that each invocation pays for
//! one Argon2 derivation (a few hundred milliseconds by default).
//!
//! What sesame does **not** defend against: malware running as you, a
//! debugger or memory dump of a live process, a weak password, or someone who
//! can both read the file and guess the password offline. Secrets are wiped
//! from memory on drop on a best-effort basis only.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod error;
mod format;
mod fsutil;
mod item;
mod kdf;
mod secret;
mod store;
mod wallet;

pub use error::{Error, Result};
pub use item::{
    Attributes, DEFAULT_CONTENT_TYPE, Item, NewItem, PutOutcome, Vault, validate_attributes,
};
pub use kdf::{KEY_LEN, KdfParams, SALT_LEN};
pub use secret::Secret;
pub use store::{DEFAULT_WALLET, Store, WALLET_EXTENSION, default_dir, validate_wallet_name};
pub use wallet::Wallet;
