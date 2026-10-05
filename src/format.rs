//! The on-disk wallet format.
//!
//! A wallet is a single file:
//!
//! ```text
//! offset  size  field
//! ------  ----  -----------------------------------------------------------
//!      0     6  magic            "SESAME"
//!      6     1  format version   1
//!      7     1  KDF id           1 = Argon2id, version 0x13
//!      8     4  Argon2 memory    KiB, little-endian u32
//!     12     4  Argon2 passes    little-endian u32
//!     16     4  Argon2 lanes     little-endian u32
//!     20     1  cipher id        1 = XChaCha20-Poly1305
//!     21    32  salt             random, fixed for the life of a key
//!     53    24  nonce            random, fresh for every write
//!     77     n  ciphertext       encrypted payload
//!   77+n    16  tag              Poly1305 authentication tag
//! ```
//!
//! The 77 header bytes are authenticated as associated data, so no field can
//! be altered without detection. The payload is the JSON-serialised
//! [`Vault`], with secrets base64-encoded. Everything about the contents,
//! including labels and attributes, is inside the ciphertext. The only things
//! an observer of the file learns are the KDF cost and the approximate size.
//!
//! Keys come from the password via Argon2id with the stored salt and
//! parameters. A new nonce is drawn from the OS RNG on every save; 192-bit
//! random nonces make accidental reuse under one key negligible, which is what
//! lets the salt (and hence the key) stay fixed across saves.

use chacha20poly1305::{AeadInOut, Key as AeadKey, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result, fill_random},
    item::Vault,
    kdf::{KEY_LEN, KdfParams, SALT_LEN},
};

const MAGIC: &[u8; 6] = b"SESAME";
const FORMAT_VERSION: u8 = 1;
const KDF_ARGON2ID_V13: u8 = 1;
const CIPHER_XCHACHA20_POLY1305: u8 = 1;

pub(crate) const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
pub(crate) const HEADER_LEN: usize = 6 + 1 + 1 + 4 + 4 + 4 + 1 + SALT_LEN + NONCE_LEN;

/// Refuse to read files larger than this. Guards against pointing sesame at
/// some unrelated huge file, and bounds memory use.
pub(crate) const MAX_FILE_LEN: usize = 64 * 1024 * 1024;

/// The authenticated, unencrypted front of a wallet file.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Header {
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let mut w = Cursor::new(&mut out);
        w.put(MAGIC);
        w.put(&[FORMAT_VERSION, KDF_ARGON2ID_V13]);
        w.put(&self.kdf.memory_kib().to_le_bytes());
        w.put(&self.kdf.iterations().to_le_bytes());
        w.put(&self.kdf.parallelism().to_le_bytes());
        w.put(&[CIPHER_XCHACHA20_POLY1305]);
        w.put(&self.salt);
        w.put(&self.nonce);
        debug_assert_eq!(w.pos, HEADER_LEN);
        out
    }

    /// Parse and validate a header. Everything here is attacker-controlled
    /// until the tag has been checked, so be strict.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Header> {
        if bytes.len() < HEADER_LEN + TAG_LEN {
            return Err(Error::Corrupt("file is too short"));
        }
        let mut r = Reader { bytes, pos: 0 };
        if r.take(MAGIC.len()) != MAGIC {
            return Err(Error::Corrupt("not a sesame wallet (bad magic)"));
        }
        let version = r.u8();
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        if r.u8() != KDF_ARGON2ID_V13 {
            return Err(Error::Corrupt("unknown key-derivation function"));
        }
        let memory = r.u32();
        let iterations = r.u32();
        let lanes = r.u32();
        let kdf = KdfParams::new(memory, iterations, lanes)?;
        if r.u8() != CIPHER_XCHACHA20_POLY1305 {
            return Err(Error::Corrupt("unknown cipher"));
        }
        let salt = r.array::<SALT_LEN>();
        let nonce = r.array::<NONCE_LEN>();
        debug_assert_eq!(r.pos, HEADER_LEN);
        Ok(Header { kdf, salt, nonce })
    }
}

/// Encrypt `vault` under `key` with a fresh nonce, returning the complete file.
pub(crate) fn seal(
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    key: &[u8; KEY_LEN],
    vault: &Vault,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let header = Header { kdf, salt, nonce }.encode();

    // Serialise straight into the output buffer, sized exactly up front so it
    // never reallocates (a realloc would strand an unwiped plaintext copy).
    let payload_len = json_len(vault)?;
    let total = HEADER_LEN + payload_len + TAG_LEN;
    if total > MAX_FILE_LEN {
        return Err(Error::TooLarge);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&header);
    vault
        .write_json(&mut *out)
        .map_err(|_| Error::Corrupt("could not serialise"))?;
    debug_assert_eq!(out.len(), HEADER_LEN + payload_len);

    let cipher = cipher(key);
    let tag = cipher
        .encrypt_inout_detached(&xnonce(&nonce), &header, (&mut out[HEADER_LEN..]).into())
        .map_err(|_| Error::TooLarge)?;
    out.extend_from_slice(&tag);

    // What remains is ciphertext, safe to hand out.
    Ok(std::mem::take(&mut *out))
}

/// Authenticate and decrypt a wallet file.
pub(crate) fn open(file: Vec<u8>, key: &[u8; KEY_LEN]) -> Result<Vault> {
    let header = Header::decode(&file)?;
    // From here on the buffer will hold plaintext.
    let mut buf = Zeroizing::new(file);

    let (aad, rest) = buf.split_at_mut(HEADER_LEN);
    let (body, tag) = rest.split_at_mut(rest.len() - TAG_LEN);
    let tag = Tag::try_from(&*tag).map_err(|_| Error::Corrupt("bad tag"))?;

    cipher(key)
        .decrypt_inout_detached(&xnonce(&header.nonce), aad, (&mut *body).into(), &tag)
        .map_err(|_| Error::Authentication)?;

    Vault::from_json(body).map_err(|_| Error::Corrupt("payload could not be parsed"))
}

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&AeadKey::from(*key))
}

fn xnonce(nonce: &[u8; NONCE_LEN]) -> XNonce {
    XNonce::from(*nonce)
}

/// Exact serialised length of `vault`, computed without allocating.
fn json_len(vault: &Vault) -> Result<usize> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut c = Count(0);
    vault
        .write_json(&mut c)
        .map_err(|_| Error::Corrupt("could not serialise"))?;
    Ok(c.0)
}

/// Sequential writer into a fixed array.
struct Cursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn put(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }
}

/// Sequential reader over a slice already known to be long enough.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        s
    }
    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.array::<4>())
    }
    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N));
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Attributes, NewItem};

    const KDF: fn() -> KdfParams = || KdfParams::new(8, 1, 1).unwrap();
    const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
    const SALT: [u8; SALT_LEN] = [0x11; SALT_LEN];

    fn sample() -> Vault {
        let mut v = Vault::default();
        let mut a = Attributes::new();
        a.insert("service".into(), "example".into());
        v.put(NewItem::new("example", "s3cret-value").attributes(a), true)
            .unwrap();
        v
    }

    fn sealed() -> Vec<u8> {
        seal(KDF(), SALT, &KEY, &sample()).unwrap()
    }

    #[test]
    fn layout_constants_agree_with_the_documented_format() {
        assert_eq!(HEADER_LEN, 77);
        let file = sealed();
        assert_eq!(&file[..6], b"SESAME");
        assert_eq!(file[6], 1, "version");
        assert_eq!(file[7], 1, "kdf id");
        assert_eq!(u32::from_le_bytes(file[8..12].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(file[12..16].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(file[16..20].try_into().unwrap()), 1);
        assert_eq!(file[20], 1, "cipher id");
        assert_eq!(&file[21..53], &SALT);
    }

    #[test]
    fn roundtrip() {
        let v = open(sealed(), &KEY).unwrap();
        assert_eq!(v.items().len(), 1);
        assert_eq!(v.items()[0].secret.expose(), b"s3cret-value");
        assert!(!v.is_dirty());
    }

    #[test]
    fn plaintext_is_not_visible_in_the_file() {
        let file = sealed();
        let hay = String::from_utf8_lossy(&file);
        for needle in ["s3cret-value", "example", "service", "label"] {
            assert!(!hay.contains(needle), "{needle:?} leaked into the file");
        }
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let a = sealed();
        let b = sealed();
        assert_ne!(a[53..77], b[53..77]);
        assert_ne!(a[77..], b[77..]);
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let mut other = KEY;
        other[0] ^= 1;
        assert!(matches!(open(sealed(), &other), Err(Error::Authentication)));
    }

    #[test]
    fn flipping_any_single_byte_is_detected() {
        let file = sealed();
        for i in 0..file.len() {
            let mut bad = file.clone();
            bad[i] ^= 0x01;
            let err = open(bad, &KEY).expect_err(&format!("byte {i} flip was not detected"));
            // Header corruption may be caught structurally first; anything
            // else must be caught by the tag. Nothing may succeed.
            assert!(
                matches!(
                    err,
                    Error::Authentication
                        | Error::Corrupt(_)
                        | Error::UnsupportedVersion(_)
                        | Error::InvalidKdfParams(_)
                ),
                "byte {i}: unexpected error {err:?}"
            );
        }
    }

    #[test]
    fn header_fields_are_authenticated_even_when_still_structurally_valid() {
        // Changing the KDF memory from 8 to 9 KiB yields a header that parses
        // fine; only the AEAD associated data check can catch it.
        let mut bad = sealed();
        bad[8] = 9;
        assert!(Header::decode(&bad).is_ok());
        assert!(matches!(open(bad, &KEY), Err(Error::Authentication)));
    }

    #[test]
    fn truncation_is_detected_at_every_length() {
        let file = sealed();
        for len in 0..file.len() {
            assert!(open(file[..len].to_vec(), &KEY).is_err(), "len {len}");
        }
    }

    #[test]
    fn appended_garbage_is_detected() {
        let mut file = sealed();
        file.push(0);
        assert!(open(file, &KEY).is_err());
    }

    #[test]
    fn rejects_bad_magic_and_unknown_versions() {
        let mut f = sealed();
        f[0] = b'X';
        assert!(matches!(Header::decode(&f), Err(Error::Corrupt(_))));

        let mut f = sealed();
        f[6] = 2;
        assert!(matches!(
            Header::decode(&f),
            Err(Error::UnsupportedVersion(2))
        ));

        let mut f = sealed();
        f[7] = 9;
        assert!(matches!(Header::decode(&f), Err(Error::Corrupt(_))));

        let mut f = sealed();
        f[20] = 9;
        assert!(matches!(Header::decode(&f), Err(Error::Corrupt(_))));
    }

    #[test]
    fn hostile_kdf_parameters_are_rejected_before_any_work_is_done() {
        let mut f = sealed();
        f[8..12].copy_from_slice(&u32::MAX.to_le_bytes()); // ~4 TiB of memory
        assert!(matches!(
            Header::decode(&f),
            Err(Error::InvalidKdfParams(_))
        ));

        let mut f = sealed();
        f[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Header::decode(&f),
            Err(Error::InvalidKdfParams(_))
        ));

        let mut f = sealed();
        f[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            Header::decode(&f),
            Err(Error::InvalidKdfParams(_))
        ));
    }

    #[test]
    fn header_roundtrips() {
        let h = Header {
            kdf: KdfParams::new(64, 2, 3).unwrap(),
            salt: [9; SALT_LEN],
            nonce: [8; NONCE_LEN],
        };
        let mut file = h.encode().to_vec();
        file.extend_from_slice(&[0; TAG_LEN]);
        let back = Header::decode(&file).unwrap();
        assert_eq!(back.kdf, h.kdf);
        assert_eq!(back.salt, h.salt);
        assert_eq!(back.nonce, h.nonce);
    }

    #[test]
    fn empty_vault_roundtrips() {
        let file = seal(KDF(), SALT, &KEY, &Vault::default()).unwrap();
        assert!(open(file, &KEY).unwrap().items().is_empty());
    }

    #[test]
    fn json_len_is_exact() {
        let v = sample();
        let mut real = Vec::new();
        v.write_json(&mut real).unwrap();
        assert_eq!(json_len(&v).unwrap(), real.len());
    }
}
