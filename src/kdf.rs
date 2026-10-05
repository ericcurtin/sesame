//! Password to key derivation (Argon2id).

use argon2::{Algorithm, Argon2, Block, Params, Version};
use unicode_normalization::{UnicodeNormalization, is_nfc};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Length of the derived encryption key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of the random salt in bytes.
pub const SALT_LEN: usize = 32;

/// A derived encryption key. Wiped on drop.
pub(crate) type Key = Zeroizing<[u8; KEY_LEN]>;

/// Argon2id cost parameters.
///
/// They are stored in the wallet header, so a wallet always opens with the
/// parameters it was created with, and the cost can be raised later with
/// [`Wallet::change_password`](crate::Wallet::change_password).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl KdfParams {
    /// Smallest accepted memory cost, in KiB. Argon2's own floor.
    pub const MIN_MEMORY_KIB: u32 = 8;
    /// Largest accepted memory cost, in KiB (1 GiB).
    ///
    /// Parameters are read from the wallet file before any authentication, so
    /// they have to be bounded to stop a hostile file from demanding absurd
    /// amounts of memory or time.
    pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
    /// Largest accepted iteration count.
    pub const MAX_ITERATIONS: u32 = 64;
    /// Largest accepted parallelism.
    pub const MAX_PARALLELISM: u32 = 16;

    /// 64 MiB, 3 passes, 1 lane.
    ///
    /// This is RFC 9106's second recommended profile. It takes a few hundred
    /// milliseconds on current hardware, which is the price of every
    /// invocation because there is no daemon to cache the unlocked key.
    pub const DEFAULT: KdfParams = KdfParams {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Validate and build a parameter set.
    ///
    /// `memory_kib` must be at least `8 * parallelism`. Values below
    /// [`KdfParams::DEFAULT`] weaken the wallet against password guessing and
    /// are only appropriate for tests.
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self> {
        if parallelism == 0 || parallelism > Self::MAX_PARALLELISM {
            return Err(Error::InvalidKdfParams("parallelism out of range"));
        }
        if memory_kib < Self::MIN_MEMORY_KIB.max(8 * parallelism) {
            return Err(Error::InvalidKdfParams("memory cost too low"));
        }
        if memory_kib > Self::MAX_MEMORY_KIB {
            return Err(Error::InvalidKdfParams("memory cost too high"));
        }
        if iterations == 0 || iterations > Self::MAX_ITERATIONS {
            return Err(Error::InvalidKdfParams("iteration count out of range"));
        }
        Ok(KdfParams {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// Memory cost in KiB.
    #[must_use]
    pub fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Number of passes over memory.
    #[must_use]
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Number of lanes.
    #[must_use]
    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams::DEFAULT
    }
}

/// Bring a password into a canonical form so that the same text typed on
/// different platforms or input methods yields the same key.
///
/// Passwords are normalised to Unicode NFC. (Not NFKC: compatibility mappings
/// would make visibly different passwords equal and so reduce entropy.)
fn normalize(password: &str) -> Result<Zeroizing<String>> {
    if password.is_empty() {
        return Err(Error::InvalidPassword("must not be empty"));
    }
    if is_nfc(password) {
        return Ok(Zeroizing::new(password.to_owned()));
    }
    // NFC output can be longer than its input; over-reserve so the buffer does
    // not reallocate (and leave an unwiped copy behind) in practice.
    let mut out = Zeroizing::new(String::with_capacity(password.len().saturating_mul(4)));
    out.extend(password.nfc());
    Ok(out)
}

/// Derive the wallet encryption key.
pub(crate) fn derive_key(password: &str, salt: &[u8; SALT_LEN], params: &KdfParams) -> Result<Key> {
    let password = normalize(password)?;

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::InvalidKdfParams("rejected by argon2"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    // Supply the working memory ourselves rather than letting argon2 allocate
    // it: the library frees it without wiping, and the matrix is derived from
    // the password.
    let blocks = argon.params().block_count();
    let mut memory: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(blocks)
        .map_err(|_| Error::OutOfMemory)?;
    memory.resize(blocks, Block::default());

    let mut key: Key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into_with_memory(password.as_bytes(), salt, &mut key[..], &mut memory[..])
        .map_err(|_| Error::InvalidKdfParams("rejected by argon2"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams::new(8, 1, 1).unwrap()
    }

    #[test]
    fn params_validation() {
        assert!(KdfParams::new(8, 1, 1).is_ok());
        assert!(KdfParams::new(7, 1, 1).is_err());
        assert!(KdfParams::new(8, 0, 1).is_err());
        assert!(KdfParams::new(8, 1, 0).is_err());
        // memory must be at least 8 KiB per lane
        assert!(KdfParams::new(8, 1, 2).is_err());
        assert!(KdfParams::new(16, 1, 2).is_ok());
        assert!(KdfParams::new(KdfParams::MAX_MEMORY_KIB, 1, 1).is_ok());
        assert!(KdfParams::new(KdfParams::MAX_MEMORY_KIB + 1, 1, 1).is_err());
        assert!(KdfParams::new(8, KdfParams::MAX_ITERATIONS + 1, 1).is_err());
        assert!(KdfParams::new(1 << 20, 1, KdfParams::MAX_PARALLELISM + 1).is_err());
        assert_eq!(KdfParams::default(), KdfParams::DEFAULT);
    }

    #[test]
    fn derivation_is_deterministic_and_input_sensitive() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key("correct horse", &salt, &fast()).unwrap();
        let b = derive_key("correct horse", &salt, &fast()).unwrap();
        assert_eq!(*a, *b);

        let other_pw = derive_key("correct horsf", &salt, &fast()).unwrap();
        assert_ne!(*a, *other_pw);

        let mut salt2 = salt;
        salt2[0] ^= 1;
        let other_salt = derive_key("correct horse", &salt2, &fast()).unwrap();
        assert_ne!(*a, *other_salt);

        let other_cost =
            derive_key("correct horse", &salt, &KdfParams::new(16, 1, 1).unwrap()).unwrap();
        assert_ne!(*a, *other_cost);
    }

    #[test]
    fn empty_password_is_rejected() {
        let salt = [0u8; SALT_LEN];
        assert!(matches!(
            derive_key("", &salt, &fast()),
            Err(Error::InvalidPassword(_))
        ));
    }

    #[test]
    fn canonically_equivalent_passwords_derive_the_same_key() {
        let salt = [1u8; SALT_LEN];
        // "é" as one code point (NFC) vs "e" + combining acute (NFD).
        let composed = derive_key("caf\u{e9}", &salt, &fast()).unwrap();
        let decomposed = derive_key("cafe\u{301}", &salt, &fast()).unwrap();
        assert_eq!(*composed, *decomposed);
    }

    #[test]
    fn compatibility_equivalent_passwords_stay_distinct() {
        let salt = [1u8; SALT_LEN];
        // U+FB01 LATIN SMALL LIGATURE FI is only NFKC-equivalent to "fi".
        let ligature = derive_key("\u{fb01}sh", &salt, &fast()).unwrap();
        let plain = derive_key("fish", &salt, &fast()).unwrap();
        assert_ne!(*ligature, *plain);
    }

    #[test]
    fn matches_an_independent_argon2id_implementation() {
        // This value is *not* just our own output pinned in place: it was
        // produced by OpenSSL's separate Argon2 implementation:
        //
        //   openssl kdf -keylen 32 -kdfopt pass:password \
        //     -kdfopt hexsalt:<32 x 02> -kdfopt iter:3 -kdfopt memcost:32 \
        //     -kdfopt lanes:4 -kdfopt threads:1 -kdfopt version:19 ARGON2ID
        //
        // It confirms the variant (id), version (0x13) and parameter meaning.
        // It also guards compatibility: if it changes, existing wallets stop
        // opening.
        let salt = [0x02u8; SALT_LEN];
        let key = derive_key("password", &salt, &KdfParams::new(32, 3, 4).unwrap()).unwrap();
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "b222fc5adb4d26d20e28e664701541b578eace38bed5b00b5302227074dfa517"
        );
    }
}
