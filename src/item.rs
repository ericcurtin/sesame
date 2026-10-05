//! Items and the decrypted vault that holds them.
//!
//! The data model follows the freedesktop Secret Service: an item is a
//! secret plus a human-readable label plus a dictionary of string
//! *attributes*, and items are found by attribute match rather than by name.

use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result, fill_random},
    secret::{Secret, serde_b64},
};

/// Item attributes: a sorted string-to-string dictionary.
pub type Attributes = BTreeMap<String, String>;

/// Content type given to items that don't specify one.
pub const DEFAULT_CONTENT_TYPE: &str = "text/plain";

const MAX_LABEL_LEN: usize = 1024;
const MAX_ATTR_KEY_LEN: usize = 256;
const MAX_ATTR_VALUE_LEN: usize = 4096;
const MAX_CONTENT_TYPE_LEN: usize = 255;

/// Seconds since the Unix epoch.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn default_content_type() -> String {
    DEFAULT_CONTENT_TYPE.to_owned()
}

/// A stored secret and its metadata.
///
/// `Item` intentionally does not implement `Serialize`: it holds a secret, and
/// a derived serialiser would make it one careless `to_string` away from
/// writing that secret to a log or an API response. (Neither does [`Vault`].)
///
/// The helper below compiles for a type that *is* `Serialize`...
///
/// ```
/// fn assert_serialize<T: serde::Serialize>() {}
/// assert_serialize::<String>();
/// ```
///
/// ...and refuses the types that hold secrets:
///
/// ```compile_fail
/// fn assert_serialize<T: serde::Serialize>() {}
/// assert_serialize::<sesame::Item>();
/// ```
///
/// ```compile_fail
/// fn assert_serialize<T: serde::Serialize>() {}
/// assert_serialize::<sesame::Vault>();
/// ```
#[derive(Clone, Debug)]
pub struct Item {
    /// Random, unique, immutable identifier: 32 lowercase hex digits.
    pub id: String,
    /// Human-readable description.
    pub label: String,
    /// Lookup attributes.
    pub attributes: Attributes,
    /// MIME type of the secret. Informational only.
    pub content_type: String,
    /// The secret itself.
    pub secret: Secret,
    /// When the item was created (seconds since the Unix epoch).
    pub created_at: u64,
    /// When the item was last changed (seconds since the Unix epoch).
    pub modified_at: u64,
}

impl Item {
    /// Whether every `(key, value)` in `query` is present in this item's
    /// attributes. An empty query matches everything.
    #[must_use]
    pub fn matches(&self, query: &Attributes) -> bool {
        query
            .iter()
            .all(|(k, v)| self.attributes.get(k).is_some_and(|have| have == v))
    }
}

/// An item that is about to be stored.
#[derive(Clone, Debug)]
pub struct NewItem {
    /// Human-readable description.
    pub label: String,
    /// Lookup attributes.
    pub attributes: Attributes,
    /// MIME type of the secret.
    pub content_type: String,
    /// The secret itself.
    pub secret: Secret,
}

impl NewItem {
    /// A new item with no attributes and the default content type.
    pub fn new(label: impl Into<String>, secret: impl Into<Secret>) -> Self {
        NewItem {
            label: label.into(),
            attributes: Attributes::new(),
            content_type: default_content_type(),
            secret: secret.into(),
        }
    }

    /// Add or overwrite one attribute.
    #[must_use]
    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Replace all attributes.
    #[must_use]
    pub fn attributes(mut self, attributes: Attributes) -> Self {
        self.attributes = attributes;
        self
    }

    /// Set the content type.
    #[must_use]
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = content_type.into();
        self
    }

    fn validate(&self) -> Result<()> {
        if self.label.len() > MAX_LABEL_LEN {
            return Err(Error::InvalidItem(format!(
                "label is longer than {MAX_LABEL_LEN} bytes"
            )));
        }
        if self.content_type.is_empty() || self.content_type.len() > MAX_CONTENT_TYPE_LEN {
            return Err(Error::InvalidItem(format!(
                "content type must be 1 to {MAX_CONTENT_TYPE_LEN} bytes"
            )));
        }
        validate_attributes(&self.attributes)
    }
}

/// Check that attribute keys and values are within limits.
pub fn validate_attributes(attributes: &Attributes) -> Result<()> {
    for (k, v) in attributes {
        if k.is_empty() {
            return Err(Error::InvalidItem(
                "attribute names must not be empty".into(),
            ));
        }
        if k.contains('=') {
            return Err(Error::InvalidItem(
                "attribute names must not contain '='".into(),
            ));
        }
        if k.len() > MAX_ATTR_KEY_LEN {
            return Err(Error::InvalidItem(format!(
                "attribute names are limited to {MAX_ATTR_KEY_LEN} bytes"
            )));
        }
        if v.len() > MAX_ATTR_VALUE_LEN {
            return Err(Error::InvalidItem(format!(
                "attribute values are limited to {MAX_ATTR_VALUE_LEN} bytes"
            )));
        }
    }
    Ok(())
}

/// What [`Vault::put`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PutOutcome {
    /// Id of the created or updated item.
    pub id: String,
    /// `true` if an existing item was overwritten, `false` if a new one was created.
    pub replaced: bool,
}

/// The decrypted contents of a wallet.
///
/// Obtained inside [`Wallet::read`](crate::Wallet::read) and
/// [`Wallet::update`](crate::Wallet::update); it never outlives the call.
#[derive(Debug, Default)]
pub struct Vault {
    items: Vec<Item>,
    /// Set by every mutating method so unchanged vaults aren't rewritten.
    dirty: bool,
}

// ---- storage representation ------------------------------------------------
//
// The JSON payload is described by private mirror types so that neither `Item`
// nor `Vault` has a public `Serialize` impl (see the note on `Item`).
//
// Reading is strict (`deny_unknown_fields`): a field this build doesn't know
// about was written by a newer sesame, and silently dropping it on the next
// save would lose data. Failing loudly is the safe choice; incompatible
// changes also bump the header's format version.

#[derive(Serialize)]
struct ItemOut<'a> {
    id: &'a str,
    label: &'a str,
    attributes: &'a Attributes,
    content_type: &'a str,
    #[serde(serialize_with = "serialize_secret")]
    secret: &'a Secret,
    created_at: u64,
    modified_at: u64,
}

fn serialize_secret<S: serde::Serializer>(secret: &&Secret, s: S) -> Result<S::Ok, S::Error> {
    serde_b64::serialize(secret, s)
}

#[derive(Serialize)]
struct VaultOut<'a> {
    items: Vec<ItemOut<'a>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemIn {
    id: String,
    label: String,
    attributes: Attributes,
    #[serde(default = "default_content_type")]
    content_type: String,
    #[serde(deserialize_with = "serde_b64::deserialize")]
    secret: Secret,
    created_at: u64,
    modified_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultIn {
    #[serde(default)]
    items: Vec<ItemIn>,
}

impl From<ItemIn> for Item {
    fn from(i: ItemIn) -> Self {
        Item {
            id: i.id,
            label: i.label,
            attributes: i.attributes,
            content_type: i.content_type,
            secret: i.secret,
            created_at: i.created_at,
            modified_at: i.modified_at,
        }
    }
}

impl Vault {
    /// Serialise to the JSON payload format.
    pub(crate) fn write_json(&self, writer: impl std::io::Write) -> serde_json::Result<()> {
        let out = VaultOut {
            items: self
                .items
                .iter()
                .map(|i| ItemOut {
                    id: &i.id,
                    label: &i.label,
                    attributes: &i.attributes,
                    content_type: &i.content_type,
                    secret: &i.secret,
                    created_at: i.created_at,
                    modified_at: i.modified_at,
                })
                .collect(),
        };
        serde_json::to_writer(writer, &out)
    }

    /// Parse the JSON payload format. The result is clean (not dirty).
    pub(crate) fn from_json(bytes: &[u8]) -> serde_json::Result<Vault> {
        let v: VaultIn = serde_json::from_slice(bytes)?;
        Ok(Vault {
            items: v.items.into_iter().map(Item::from).collect(),
            dirty: false,
        })
    }

    /// Every item, in insertion order.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// Whether this vault has been modified since it was loaded.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// All items matching `query`, ordered by label, then creation time, then id.
    #[must_use]
    pub fn search(&self, query: &Attributes) -> Vec<&Item> {
        let mut found: Vec<&Item> = self.items.iter().filter(|i| i.matches(query)).collect();
        found.sort_by(|a, b| {
            a.label
                .cmp(&b.label)
                .then(a.created_at.cmp(&b.created_at))
                .then(a.id.cmp(&b.id))
        });
        found
    }

    /// Look an item up by id or by an unambiguous prefix of its id.
    pub fn get(&self, id_or_prefix: &str) -> Result<&Item> {
        if id_or_prefix.is_empty() {
            return Err(Error::ItemNotFound);
        }
        // An exact id always wins, even if it is also a prefix of another.
        if let Some(exact) = self.items.iter().find(|i| i.id == id_or_prefix) {
            return Ok(exact);
        }
        let mut hits = self.items.iter().filter(|i| i.id.starts_with(id_or_prefix));
        match (hits.next(), hits.next()) {
            (None, _) => Err(Error::ItemNotFound),
            (Some(only), None) => Ok(only),
            (Some(_), Some(_)) => Err(Error::AmbiguousId),
        }
    }

    /// Store an item.
    ///
    /// If `replace` is set and the item has at least one attribute, an
    /// existing item with *exactly* the same attributes is overwritten in place
    /// (keeping its id and creation time) instead of a duplicate being added.
    /// This mirrors `secret-tool store` and makes "save the password for X"
    /// idempotent.
    pub fn put(&mut self, new: NewItem, replace: bool) -> Result<PutOutcome> {
        new.validate()?;
        let now = now();

        if replace
            && !new.attributes.is_empty()
            && let Some(existing) = self
                .items
                .iter_mut()
                .find(|i| i.attributes == new.attributes)
        {
            existing.label = new.label;
            existing.content_type = new.content_type;
            existing.secret = new.secret;
            existing.modified_at = now.max(existing.created_at);
            self.dirty = true;
            return Ok(PutOutcome {
                id: existing.id.clone(),
                replaced: true,
            });
        }

        let id = new_id(&self.items)?;
        self.items.push(Item {
            id: id.clone(),
            label: new.label,
            attributes: new.attributes,
            content_type: new.content_type,
            secret: new.secret,
            created_at: now,
            modified_at: now,
        });
        self.dirty = true;
        Ok(PutOutcome {
            id,
            replaced: false,
        })
    }

    /// Remove the item with exactly this id.
    pub fn remove(&mut self, id: &str) -> Result<Item> {
        let idx = self
            .items
            .iter()
            .position(|i| i.id == id)
            .ok_or(Error::ItemNotFound)?;
        self.dirty = true;
        Ok(self.items.remove(idx))
    }

    /// Remove every item matching `query`, returning how many were removed.
    pub fn remove_matching(&mut self, query: &Attributes) -> usize {
        let before = self.items.len();
        self.items.retain(|i| !i.matches(query));
        let removed = before - self.items.len();
        if removed > 0 {
            self.dirty = true;
        }
        removed
    }
}

/// A fresh random id that doesn't collide with an existing one.
fn new_id(existing: &[Item]) -> Result<String> {
    loop {
        let mut raw = [0u8; 16];
        fill_random(&mut raw)?;
        let id = hex(&raw);
        if existing.iter().all(|i| i.id != id) {
            return Ok(id);
        }
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str)]) -> Attributes {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn item(label: &str, pairs: &[(&str, &str)], secret: &str) -> NewItem {
        NewItem::new(label, secret).attributes(attrs(pairs))
    }

    #[test]
    fn put_then_search_by_subset_of_attributes() {
        let mut v = Vault::default();
        v.put(
            item("gh", &[("service", "github"), ("user", "ann")], "s1"),
            true,
        )
        .unwrap();
        v.put(
            item("gl", &[("service", "gitlab"), ("user", "ann")], "s2"),
            true,
        )
        .unwrap();

        assert_eq!(v.search(&attrs(&[])).len(), 2, "empty query matches all");
        assert_eq!(v.search(&attrs(&[("user", "ann")])).len(), 2);
        let hit = v.search(&attrs(&[("service", "github")]));
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].secret.expose(), b"s1");
        assert!(
            v.search(&attrs(&[("service", "github"), ("user", "bob")]))
                .is_empty()
        );
        assert!(v.search(&attrs(&[("nope", "x")])).is_empty());
        // values compare exactly, not by prefix
        assert!(v.search(&attrs(&[("service", "git")])).is_empty());
    }

    #[test]
    fn put_replaces_item_with_identical_attributes() {
        let mut v = Vault::default();
        let a = v.put(item("old", &[("k", "v")], "one"), true).unwrap();
        assert!(!a.replaced);
        let created = v.get(&a.id).unwrap().created_at;

        let b = v
            .put(
                item("new", &[("k", "v")], "two").content_type("application/x-test"),
                true,
            )
            .unwrap();
        assert!(b.replaced);
        assert_eq!(a.id, b.id, "id is stable across replacement");
        assert_eq!(v.items().len(), 1);

        let got = v.get(&b.id).unwrap();
        assert_eq!(got.label, "new");
        assert_eq!(got.secret.expose(), b"two");
        assert_eq!(got.content_type, "application/x-test");
        assert_eq!(got.created_at, created);
        assert!(got.modified_at >= created);
    }

    #[test]
    fn replacement_requires_exact_attribute_set() {
        let mut v = Vault::default();
        v.put(item("a", &[("k", "v")], "1"), true).unwrap();
        // A superset or subset of attributes is a different item.
        v.put(item("b", &[("k", "v"), ("extra", "x")], "2"), true)
            .unwrap();
        v.put(item("c", &[("other", "v")], "3"), true).unwrap();
        assert_eq!(v.items().len(), 3);
    }

    #[test]
    fn no_replace_always_adds() {
        let mut v = Vault::default();
        let a = v.put(item("a", &[("k", "v")], "1"), false).unwrap();
        let b = v.put(item("a", &[("k", "v")], "2"), false).unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(v.items().len(), 2);
    }

    #[test]
    fn items_without_attributes_are_never_replaced() {
        let mut v = Vault::default();
        v.put(item("a", &[], "1"), true).unwrap();
        v.put(item("a", &[], "2"), true).unwrap();
        assert_eq!(v.items().len(), 2);
    }

    #[test]
    fn id_prefix_lookup() {
        let mut v = Vault::default();
        let a = v.put(item("a", &[("k", "1")], "1"), true).unwrap();
        v.put(item("b", &[("k", "2")], "2"), true).unwrap();

        assert_eq!(v.get(&a.id).unwrap().label, "a");
        assert_eq!(v.get(&a.id[..12]).unwrap().label, "a");
        assert!(matches!(v.get(""), Err(Error::ItemNotFound)));
        assert!(matches!(v.get("zzzz"), Err(Error::ItemNotFound)));
    }

    #[test]
    fn ambiguous_prefix_is_an_error_but_exact_id_still_resolves() {
        let mk = |id: &str, label: &str| Item {
            id: id.into(),
            label: label.into(),
            attributes: Attributes::new(),
            content_type: default_content_type(),
            secret: Secret::default(),
            created_at: 0,
            modified_at: 0,
        };
        let v = Vault {
            items: vec![mk("abc1", "one"), mk("abc2", "two"), mk("abc", "short")],
            dirty: false,
        };
        assert!(matches!(v.get("ab"), Err(Error::AmbiguousId)));
        assert_eq!(v.get("abc").unwrap().label, "short");
        assert_eq!(v.get("abc1").unwrap().label, "one");
    }

    #[test]
    fn remove_and_remove_matching() {
        let mut v = Vault::default();
        let a = v
            .put(item("a", &[("t", "x"), ("n", "1")], "1"), true)
            .unwrap();
        v.put(item("b", &[("t", "x"), ("n", "2")], "2"), true)
            .unwrap();
        v.put(item("c", &[("t", "y")], "3"), true).unwrap();

        v.remove(&a.id).unwrap();
        assert!(matches!(v.remove(&a.id), Err(Error::ItemNotFound)));
        assert_eq!(v.items().len(), 2);

        assert_eq!(v.remove_matching(&attrs(&[("t", "x")])), 1);
        assert_eq!(v.remove_matching(&attrs(&[("t", "x")])), 0);
        assert_eq!(v.items().len(), 1);
    }

    #[test]
    fn dirty_flag_tracks_mutation_only() {
        let mut v = Vault::default();
        assert!(!v.is_dirty());
        let _ = v.search(&attrs(&[]));
        assert!(!v.is_dirty());

        assert_eq!(v.remove_matching(&attrs(&[("k", "v")])), 0);
        assert!(!v.is_dirty(), "removing nothing is not a change");
        assert!(v.remove("nope").is_err());
        assert!(!v.is_dirty());

        v.put(item("a", &[("k", "v")], "1"), true).unwrap();
        assert!(v.is_dirty());
    }

    #[test]
    fn search_order_is_deterministic() {
        let mut v = Vault::default();
        v.put(item("b", &[("g", "1"), ("n", "1")], "x"), true)
            .unwrap();
        v.put(item("a", &[("g", "1"), ("n", "2")], "x"), true)
            .unwrap();
        v.put(item("c", &[("g", "1"), ("n", "3")], "x"), true)
            .unwrap();
        let labels: Vec<_> = v
            .search(&attrs(&[("g", "1")]))
            .iter()
            .map(|i| i.label.clone())
            .collect();
        assert_eq!(labels, ["a", "b", "c"]);
    }

    #[test]
    fn validation() {
        let mut v = Vault::default();
        assert!(v.put(item("a", &[("", "v")], "s"), true).is_err());
        assert!(v.put(item("a", &[("k=x", "v")], "s"), true).is_err());
        assert!(
            v.put(item("a", &[(&"k".repeat(257), "v")], "s"), true)
                .is_err()
        );
        assert!(
            v.put(item("a", &[("k", &"v".repeat(4097))], "s"), true)
                .is_err()
        );
        assert!(
            v.put(item(&"l".repeat(1025), &[("k", "v")], "s"), true)
                .is_err()
        );
        assert!(
            v.put(item("a", &[("k", "v")], "s").content_type(""), true)
                .is_err()
        );
        assert!(!v.is_dirty(), "rejected items leave the vault untouched");
        assert!(v.items().is_empty());

        // Boundaries are inclusive and non-ASCII is fine.
        assert!(
            v.put(
                item("é", &[(&"k".repeat(256), &"v".repeat(4096))], "s"),
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn ids_are_32_lowercase_hex_digits_and_unique() {
        let mut v = Vault::default();
        let mut seen = std::collections::HashSet::new();
        for n in 0..50 {
            let id = v
                .put(item("x", &[("n", &n.to_string())], "s"), true)
                .unwrap()
                .id;
            assert_eq!(id.len(), 32);
            assert!(
                id.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            assert!(seen.insert(id));
        }
    }

    #[test]
    fn json_roundtrip_preserves_everything_including_binary_secrets() {
        let mut v = Vault::default();
        let binary: Vec<u8> = (0..=255u8).collect();
        v.put(
            NewItem::new("bin", binary.clone())
                .attribute("k", "v")
                .attribute("unicode", "naïve ☃"),
            true,
        )
        .unwrap();
        v.put(item("empty", &[("e", "1")], ""), true).unwrap();

        let mut json = Vec::new();
        v.write_json(&mut json).unwrap();
        let back = Vault::from_json(&json).unwrap();
        assert!(!back.is_dirty(), "a freshly loaded vault is clean");
        assert_eq!(back.items().len(), 2);
        assert_eq!(back.items()[0].secret.expose(), &binary[..]);
        assert_eq!(back.items()[0].attributes["unicode"], "naïve ☃");
        assert!(back.items()[1].secret.is_empty());
    }

    #[test]
    fn json_does_not_contain_plain_secret() {
        let mut v = Vault::default();
        v.put(item("a", &[("k", "v")], "hunter2hunter2"), true)
            .unwrap();
        let mut json = Vec::new();
        v.write_json(&mut json).unwrap();
        let json = String::from_utf8(json).unwrap();
        assert!(!json.contains("hunter2"));
    }

    #[test]
    fn unknown_fields_are_rejected_rather_than_silently_dropped() {
        // A newer writer's extra field must not be lost by an older reader
        // that rewrites the file.
        let bad = br#"{"items":[],"future_field":1}"#;
        assert!(Vault::from_json(bad).is_err());
        let bad_item = br#"{"items":[{"id":"a","label":"l","attributes":{},"secret":"","created_at":0,"modified_at":0,"future":1}]}"#;
        assert!(Vault::from_json(bad_item).is_err());
    }

    #[test]
    fn invalid_base64_secret_is_rejected() {
        let bad = br#"{"items":[{"id":"a","label":"l","attributes":{},"secret":"!!!","created_at":0,"modified_at":0}]}"#;
        assert!(Vault::from_json(bad).is_err());
    }

    #[test]
    fn missing_content_type_defaults() {
        let json = br#"{"items":[{"id":"a","label":"l","attributes":{},"secret":"","created_at":0,"modified_at":0}]}"#;
        let v = Vault::from_json(json).unwrap();
        assert_eq!(v.items()[0].content_type, DEFAULT_CONTENT_TYPE);
    }
}
