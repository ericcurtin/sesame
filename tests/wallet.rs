//! End-to-end tests of the library against real files.

use std::{fs, path::PathBuf, sync::Barrier, thread};

use sesame::{Attributes, Error, KdfParams, NewItem, Wallet};
use tempfile::TempDir;

const PW: &str = "correct horse battery staple";

fn fast() -> KdfParams {
    KdfParams::new(8, 1, 1).unwrap()
}

fn attrs(pairs: &[(&str, &str)]) -> Attributes {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn new_wallet() -> (TempDir, PathBuf, Wallet) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.sesame");
    let wallet = Wallet::create(&path, PW, fast()).unwrap();
    (dir, path, wallet)
}

#[test]
fn secrets_survive_reopening_with_the_password() {
    let (_dir, path, wallet) = new_wallet();
    wallet
        .put(
            NewItem::new("GitHub", "ghp_abc123").attribute("service", "github"),
            true,
        )
        .unwrap();
    drop(wallet);

    let wallet = Wallet::open(&path, PW).unwrap();
    let found = wallet.search(&attrs(&[("service", "github")])).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].label, "GitHub");
    assert_eq!(found[0].secret.expose(), b"ghp_abc123");
}

#[test]
fn wrong_password_is_refused_and_leaves_the_file_alone() {
    let (_dir, path, _wallet) = new_wallet();
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        Wallet::open(&path, "wrong"),
        Err(Error::Authentication)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn create_refuses_to_overwrite_an_existing_wallet() {
    let (_dir, path, wallet) = new_wallet();
    wallet
        .put(NewItem::new("x", "y").attribute("k", "v"), true)
        .unwrap();
    let before = fs::read(&path).unwrap();

    assert!(matches!(
        Wallet::create(&path, "other password", fast()),
        Err(Error::WalletExists(_))
    ));
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "existing wallet untouched"
    );
    Wallet::open(&path, PW).unwrap();
}

#[test]
fn create_makes_missing_parent_directories() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a").join("b").join("w.sesame");
    Wallet::create(&path, PW, fast()).unwrap();
    assert!(path.is_file());
}

#[test]
fn opening_a_missing_wallet_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nope.sesame");
    assert!(matches!(
        Wallet::open(&path, PW),
        Err(Error::WalletNotFound(_))
    ));
    assert_eq!(
        fs::read_dir(dir.path()).unwrap().count(),
        0,
        "probing a missing wallet must not leave lock files behind"
    );
}

#[test]
fn a_wallet_deleted_under_an_open_handle_reports_not_found() {
    let (_dir, path, wallet) = new_wallet();
    fs::remove_file(&path).unwrap();
    assert!(matches!(wallet.list(), Err(Error::WalletNotFound(_))));
    assert!(matches!(
        wallet.put(NewItem::new("a", "b"), false),
        Err(Error::WalletNotFound(_))
    ));
}

#[test]
fn unchanged_updates_do_not_rewrite_the_file() {
    let (_dir, path, wallet) = new_wallet();
    wallet
        .put(NewItem::new("a", "b").attribute("k", "v"), true)
        .unwrap();
    let before = fs::read(&path).unwrap();

    // Reads, misses and no-op deletes must leave the bytes (including the
    // nonce) exactly as they were.
    wallet.list().unwrap();
    assert_eq!(
        wallet.delete_matching(&attrs(&[("k", "other")])).unwrap(),
        0
    );
    assert!(matches!(
        wallet.delete("deadbeef"),
        Err(Error::ItemNotFound)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);

    // A real change does rewrite, and uses a fresh nonce.
    wallet
        .put(NewItem::new("a2", "b2").attribute("k", "v2"), true)
        .unwrap();
    let after = fs::read(&path).unwrap();
    assert_ne!(after, before);
    assert_ne!(
        after[53..77],
        before[53..77],
        "nonce must change on every write"
    );
    assert_eq!(after[21..53], before[21..53], "salt is stable across saves");
}

#[test]
fn a_failing_update_writes_nothing() {
    let (_dir, path, wallet) = new_wallet();
    let before = fs::read(&path).unwrap();
    let r = wallet.update(|v| {
        v.put(NewItem::new("a", "b").attribute("k", "v"), true)?;
        Err::<(), _>(Error::InvalidItem("simulated failure".into()))
    });
    assert!(r.is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(wallet.list().unwrap().is_empty());
}

#[test]
fn replace_semantics_hold_through_the_file() {
    let (_dir, _path, wallet) = new_wallet();
    let a = wallet
        .put(NewItem::new("v1", "one").attribute("k", "v"), true)
        .unwrap();
    let b = wallet
        .put(NewItem::new("v2", "two").attribute("k", "v"), true)
        .unwrap();
    assert!(!a.replaced);
    assert!(b.replaced);
    assert_eq!(a.id, b.id);
    let all = wallet.list().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].secret.expose(), b"two");
}

#[test]
fn get_and_delete_by_id_prefix() {
    let (_dir, _path, wallet) = new_wallet();
    let a = wallet
        .put(NewItem::new("a", "1").attribute("k", "1"), true)
        .unwrap();
    wallet
        .put(NewItem::new("b", "2").attribute("k", "2"), true)
        .unwrap();

    assert_eq!(wallet.get(&a.id[..10]).unwrap().label, "a");
    wallet.delete(&a.id[..10]).unwrap();
    assert!(matches!(wallet.get(&a.id), Err(Error::ItemNotFound)));
    assert_eq!(wallet.list().unwrap().len(), 1);
}

#[test]
fn tampering_with_the_file_is_detected() {
    let (_dir, path, wallet) = new_wallet();
    wallet
        .put(NewItem::new("a", "b").attribute("k", "v"), true)
        .unwrap();
    let original = fs::read(&path).unwrap();

    // Flip a ciphertext bit.
    let mut bad = original.clone();
    bad[90] ^= 1;
    fs::write(&path, &bad).unwrap();
    assert!(matches!(
        Wallet::open(&path, PW),
        Err(Error::Authentication)
    ));
    assert!(matches!(wallet.list(), Err(Error::Authentication)));

    // Truncate it.
    fs::write(&path, &original[..original.len() - 1]).unwrap();
    assert!(Wallet::open(&path, PW).is_err());

    // Garbage that is not a wallet at all.
    fs::write(&path, b"this is not a wallet file, just some text, padded out to be long enough.....................................").unwrap();
    assert!(matches!(Wallet::open(&path, PW), Err(Error::Corrupt(_))));

    // Restoring the original makes everything work again.
    fs::write(&path, &original).unwrap();
    assert_eq!(Wallet::open(&path, PW).unwrap().list().unwrap().len(), 1);
}

#[test]
fn replaying_an_older_valid_wallet_file_is_not_detected_as_tampering() {
    // Documented limitation: authenticated encryption cannot tell an old
    // snapshot from the current one. This pins the behaviour so a change in it
    // is a conscious decision.
    let (_dir, path, wallet) = new_wallet();
    wallet
        .put(NewItem::new("a", "old").attribute("k", "v"), true)
        .unwrap();
    let snapshot = fs::read(&path).unwrap();
    wallet
        .put(NewItem::new("a", "new").attribute("k", "v"), true)
        .unwrap();

    fs::write(&path, snapshot).unwrap();
    let got = wallet.list().unwrap();
    assert_eq!(got[0].secret.expose(), b"old");
}

#[test]
fn change_password_rekeys_and_preserves_items() {
    let (_dir, path, mut wallet) = new_wallet();
    for i in 0..5 {
        wallet
            .put(
                NewItem::new(format!("item {i}"), format!("secret {i}"))
                    .attribute("n", i.to_string()),
                true,
            )
            .unwrap();
    }
    let salt_before = fs::read(&path).unwrap()[21..53].to_vec();

    let stronger = KdfParams::new(16, 2, 1).unwrap();
    wallet
        .change_password("a brand new password", stronger)
        .unwrap();
    assert_eq!(wallet.kdf_params(), stronger);

    // The handle keeps working under the new key.
    assert_eq!(wallet.list().unwrap().len(), 5);
    // Fresh salt.
    assert_ne!(fs::read(&path).unwrap()[21..53].to_vec(), salt_before);

    assert!(matches!(
        Wallet::open(&path, PW),
        Err(Error::Authentication)
    ));
    let reopened = Wallet::open(&path, "a brand new password").unwrap();
    assert_eq!(reopened.kdf_params(), stronger);
    let items = reopened.search(&attrs(&[("n", "3")])).unwrap();
    assert_eq!(items[0].secret.expose(), b"secret 3");
}

#[test]
fn other_handles_notice_a_password_change() {
    let (_dir, path, mut a) = new_wallet();
    let b = Wallet::open(&path, PW).unwrap();
    a.put(NewItem::new("x", "y").attribute("k", "v"), true)
        .unwrap();

    a.change_password("new password", fast()).unwrap();

    assert!(matches!(b.list(), Err(Error::WalletRekeyed)));
    assert!(matches!(
        b.put(NewItem::new("z", "z"), false),
        Err(Error::WalletRekeyed)
    ));
    // ...and the failed write must not have clobbered anything.
    assert_eq!(a.list().unwrap().len(), 1);
}

#[test]
fn empty_passwords_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.sesame");
    assert!(matches!(
        Wallet::create(&path, "", fast()),
        Err(Error::InvalidPassword(_))
    ));
    assert!(!path.exists());
}

#[test]
fn unicode_passwords_work_across_normalisation_forms() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.sesame");
    Wallet::create(&path, "caf\u{e9} \u{1f511}", fast()).unwrap();
    // Same text, decomposed: what a different keyboard or OS might produce.
    Wallet::open(&path, "cafe\u{301} \u{1f511}").unwrap();
}

#[test]
fn binary_and_large_secrets_roundtrip() {
    let (_dir, _path, wallet) = new_wallet();
    let binary: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
    let id = wallet
        .put(
            NewItem::new("blob", binary.clone())
                .attribute("k", "blob")
                .content_type("application/octet-stream"),
            true,
        )
        .unwrap()
        .id;
    let got = wallet.get(&id).unwrap();
    assert_eq!(got.secret.expose(), &binary[..]);
    assert_eq!(got.content_type, "application/octet-stream");
}

#[cfg(unix)]
#[test]
fn wallet_files_are_owner_only_even_after_rewrites() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, path, wallet) = new_wallet();
    wallet
        .put(NewItem::new("a", "b").attribute("k", "v"), true)
        .unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn no_plaintext_ever_reaches_the_disk() {
    let (dir, path, wallet) = new_wallet();
    wallet
        .put(
            NewItem::new("very-distinctive-label", "very-distinctive-secret")
                .attribute("distinctive-key", "distinctive-value"),
            true,
        )
        .unwrap();
    for entry in fs::read_dir(dir.path()).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("distinctive"), "plaintext found on disk");
    }
    assert!(path.is_file());
}

/// The point of the file lock: simultaneous writers must not lose updates.
#[test]
fn concurrent_writers_never_lose_updates() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 12;

    let (_dir, path, wallet) = new_wallet();
    let barrier = Barrier::new(THREADS);

    thread::scope(|s| {
        for t in 0..THREADS {
            // Separate handle per thread, as separate processes would have.
            let handle = Wallet::open(&path, PW).unwrap();
            let barrier = &barrier;
            s.spawn(move || {
                barrier.wait();
                for i in 0..PER_THREAD {
                    handle
                        .put(
                            NewItem::new(format!("t{t}-i{i}"), format!("secret-{t}-{i}"))
                                .attribute("thread", t.to_string())
                                .attribute("i", i.to_string()),
                            true,
                        )
                        .unwrap();
                }
            });
        }
    });

    let items = wallet.list().unwrap();
    assert_eq!(items.len(), THREADS * PER_THREAD, "an update was lost");
    for t in 0..THREADS {
        for i in 0..PER_THREAD {
            let hit = wallet
                .search(&attrs(&[("thread", &t.to_string()), ("i", &i.to_string())]))
                .unwrap();
            assert_eq!(hit.len(), 1, "t{t} i{i}");
            assert_eq!(hit[0].secret.expose(), format!("secret-{t}-{i}").as_bytes());
        }
    }
}

#[test]
fn readers_always_see_a_complete_consistent_wallet_while_writers_run() {
    let (_dir, path, wallet) = new_wallet();
    for i in 0..10 {
        wallet
            .put(
                NewItem::new(format!("seed{i}"), "s").attribute("seed", i.to_string()),
                true,
            )
            .unwrap();
    }

    thread::scope(|s| {
        // One writer churning the file...
        let w = Wallet::open(&path, PW).unwrap();
        s.spawn(move || {
            for i in 0..40 {
                w.put(
                    NewItem::new(format!("w{i}"), "x").attribute("w", i.to_string()),
                    true,
                )
                .unwrap();
            }
        });
        // ...while readers must never observe a torn or undecryptable file.
        for _ in 0..3 {
            let r = Wallet::open(&path, PW).unwrap();
            s.spawn(move || {
                let mut last = 0;
                for _ in 0..60 {
                    let n = r.list().expect("reader saw a torn write").len();
                    assert!(n >= 10, "seed items vanished");
                    assert!(n >= last, "item count went backwards");
                    last = n;
                }
            });
        }
    });

    assert_eq!(wallet.list().unwrap().len(), 50);
}

#[test]
fn concurrent_delete_and_put_stay_consistent() {
    let (_dir, path, wallet) = new_wallet();
    for i in 0..20 {
        wallet
            .put(
                NewItem::new(format!("d{i}"), "x").attribute("del", i.to_string()),
                true,
            )
            .unwrap();
    }

    thread::scope(|s| {
        let a = Wallet::open(&path, PW).unwrap();
        s.spawn(move || {
            for i in 0..20 {
                assert_eq!(
                    a.delete_matching(&attrs(&[("del", &i.to_string())]))
                        .unwrap(),
                    1
                );
            }
        });
        let b = Wallet::open(&path, PW).unwrap();
        s.spawn(move || {
            for i in 0..20 {
                b.put(
                    NewItem::new(format!("k{i}"), "y").attribute("keep", i.to_string()),
                    true,
                )
                .unwrap();
            }
        });
    });

    let left = wallet.list().unwrap();
    assert_eq!(left.len(), 20);
    assert!(left.iter().all(|i| i.attributes.contains_key("keep")));
}

/// A wallet written by sesame 0.1.0 and checked in as a fixture.
///
/// Two jobs. First, format stability: if a change to the on-disk format makes
/// this fail, every existing user's wallet would stop opening. Second,
/// portability: CI runs this on macOS, Linux and Windows, on x86-64 and
/// aarch64, so it proves that one file really is readable on all of them.
///
/// Regenerate (only if the format version is deliberately bumped) with:
///
/// ```text
/// printf 'p\xc3\xa4ssw\xc3\xb6rd-\xe2\x98\x83\n' > pw          # "pässwörd-☃"
/// export SESAME_DIR=./w SESAME_PASSWORD_FILE=./pw
/// sesame init --kdf-memory-mib 1 --kdf-iterations 1
/// printf 'golden-secret-1' | sesame set --label "Golden one" service=golden user=ann
/// printf '\x00\x01\x02\xff\n' | sesame set --label "Binary blob" \
///     --content-type application/octet-stream kind=binary
/// ```
#[test]
fn golden_v1_wallet_opens_with_the_expected_contents() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/golden-v1.sesame");
    // Copy first: opening a wallet creates a lock file beside it, and the
    // source tree must not be littered with those.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("golden.sesame");
    fs::copy(&fixture, &path).unwrap();

    // The fixture's password is NFC; the decomposed spelling a different
    // keyboard or OS might produce must open it too.
    let nfc = "p\u{e4}ssw\u{f6}rd-\u{2603}";
    let nfd = "pa\u{308}sswo\u{308}rd-\u{2603}";
    let wallet = Wallet::open(&path, nfc).unwrap();
    Wallet::open(&path, nfd).expect("NFD spelling of the password must work");
    assert!(matches!(
        Wallet::open(&path, "wrong"),
        Err(Error::Authentication)
    ));

    assert_eq!(wallet.kdf_params(), KdfParams::new(1024, 1, 1).unwrap());

    let items = wallet.list().unwrap();
    assert_eq!(items.len(), 2);

    let golden = &wallet.search(&attrs(&[("service", "golden")])).unwrap()[0];
    assert_eq!(golden.label, "Golden one");
    assert_eq!(
        golden.attributes,
        attrs(&[("service", "golden"), ("user", "ann")])
    );
    assert_eq!(golden.secret.expose(), b"golden-secret-1");
    assert_eq!(golden.content_type, "text/plain");

    let blob = &wallet.search(&attrs(&[("kind", "binary")])).unwrap()[0];
    assert_eq!(blob.label, "Binary blob");
    assert_eq!(blob.secret.expose(), &[0x00, 0x01, 0x02, 0xff, b'\n']);
    assert_eq!(blob.content_type, "application/octet-stream");
}
