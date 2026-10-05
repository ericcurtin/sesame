//! A byte string that is wiped from memory when dropped.

use std::fmt;

use zeroize::Zeroizing;

/// Secret bytes.
///
/// The contents are overwritten with zeros when the value is dropped, and are
/// never shown by [`Debug`](fmt::Debug). Reading them back requires an explicit
/// call to [`Secret::expose`], which keeps accidental disclosure greppable.
///
/// This is best-effort hygiene: it cannot stop the operating system from
/// paging memory to disk or a debugger from reading it.
#[derive(Clone, Default)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Take ownership of `bytes`.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(Zeroizing::new(bytes))
    }

    /// Copy `bytes` into a new secret.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Secret::new(bytes.to_vec())
    }

    /// The secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The secret as UTF-8 text, if it is valid UTF-8.
    pub fn expose_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.0)
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl From<Vec<u8>> for Secret {
    fn from(bytes: Vec<u8>) -> Self {
        Secret::new(bytes)
    }
}

impl From<&[u8]> for Secret {
    fn from(bytes: &[u8]) -> Self {
        Secret::from_slice(bytes)
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Secret::new(s.into_bytes())
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Secret::from_slice(s.as_bytes())
    }
}

/// `#[serde(with = ...)]` support: secrets are stored as base64 strings.
///
/// This is deliberately a `with` module rather than `Serialize`/`Deserialize`
/// impls on [`Secret`], so a secret can't be serialised by accident anywhere
/// else.
///
/// Encoding streams through `Display`, and decoding reads the string borrowed
/// from the (zeroized) input buffer, so no intermediate heap copy of the secret
/// is made in either direction.
pub(crate) mod serde_b64 {
    use std::fmt;

    use base64::{Engine as _, display::Base64Display, engine::general_purpose::STANDARD};
    use serde::{Deserializer, Serializer, de};
    use zeroize::Zeroizing;

    use super::Secret;

    pub fn serialize<S: Serializer>(secret: &Secret, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&Base64Display::new(secret.expose(), &STANDARD))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Secret, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = Secret;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a base64-encoded string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Secret, E> {
                // `decode_vec` resizes to exactly this estimate, so sizing the
                // buffer to it up front means no reallocation (and no stranded
                // copy of the secret).
                let mut out =
                    Zeroizing::new(Vec::with_capacity(base64::decoded_len_estimate(v.len())));
                STANDARD
                    .decode_vec(v, &mut out)
                    .map_err(|_| E::custom("invalid base64"))?;
                Ok(Secret(out))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::from("hunter2");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert!(!format!("{s:#?}").contains("hunter2"));
    }

    #[test]
    fn accessors() {
        let s = Secret::from(&b"abc"[..]);
        assert_eq!(s.expose(), b"abc");
        assert_eq!(s.expose_str().unwrap(), "abc");
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());
        assert!(Secret::default().is_empty());
        assert!(Secret::from(vec![0xff, 0xfe]).expose_str().is_err());
    }
}
