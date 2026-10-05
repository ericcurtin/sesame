//! Black-box tests of the `sesame` binary.
//!
//! These cover everything that works without a terminal. Interactive prompting
//! needs a pty and is exercised by hand.
//!
//! Every invocation is given a password source (`SESAME_PASSWORD_FILE`, or an
//! explicit stdin/file option). Without one the binary would prompt on the
//! developer's controlling terminal, which would hang the test run.

use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_sesame");
const PASSWORD: &str = "correct horse battery staple";
/// 1 MiB, 1 pass: fast, and plenty for tests.
const FAST_KDF: [&str; 4] = ["--kdf-memory-mib", "1", "--kdf-iterations", "1"];

struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

impl Out {
    fn stdout_str(&self) -> String {
        String::from_utf8(self.stdout.clone()).expect("stdout is UTF-8")
    }
    #[track_caller]
    fn ok(self) -> Out {
        assert_eq!(self.code, 0, "expected success, stderr: {}", self.stderr);
        self
    }
    #[track_caller]
    fn code(self, expected: i32) -> Out {
        assert_eq!(
            self.code,
            expected,
            "unexpected exit code; stdout: {:?} stderr: {}",
            String::from_utf8_lossy(&self.stdout),
            self.stderr
        );
        self
    }
}

struct Env {
    _root: TempDir,
    dir: PathBuf,
    password_file: PathBuf,
}

impl Env {
    fn new() -> Env {
        let root = tempfile::tempdir().unwrap();
        let password_file = root.path().join("password");
        fs::write(&password_file, format!("{PASSWORD}\n")).unwrap();
        Env {
            dir: root.path().join("wallets"),
            password_file,
            _root: root,
        }
    }

    /// A command isolated from the developer's own sesame configuration.
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env_remove("SESAME_WALLET")
            .env("SESAME_DIR", &self.dir)
            .env("SESAME_PASSWORD_FILE", &self.password_file);
        cmd
    }

    fn run(&self, args: &[&str]) -> Out {
        exec(self.command(args), None)
    }

    fn run_with_stdin(&self, args: &[&str], stdin: &[u8]) -> Out {
        exec(self.command(args), Some(stdin))
    }

    fn init(&self) {
        let mut args = vec!["init"];
        args.extend(FAST_KDF);
        self.run(&args).ok();
    }

    fn set(&self, attrs: &[&str], secret: &[u8]) -> Out {
        let mut args = vec!["set"];
        args.extend(attrs);
        self.run_with_stdin(&args, secret)
    }

    fn get(&self, attrs: &[&str]) -> Out {
        let mut args = vec!["get"];
        args.extend(attrs);
        self.run(&args)
    }

    fn wallet_file(&self) -> PathBuf {
        self.dir.join("default.sesame")
    }
}

fn exec(mut cmd: Command, stdin: Option<&[u8]>) -> Out {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    match stdin {
        Some(_) => cmd.stdin(Stdio::piped()),
        None => cmd.stdin(Stdio::null()),
    };
    let mut child = cmd.spawn().expect("spawn sesame");
    if let Some(bytes) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        // The child may exit without reading (usage errors); that's fine.
        let _ = pipe.write_all(bytes);
    }
    let out = child.wait_with_output().unwrap();
    Out {
        code: out.status.code().expect("terminated by signal"),
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

// ---- init ------------------------------------------------------------------

#[test]
fn init_creates_a_wallet_and_refuses_to_overwrite_it() {
    let env = Env::new();
    env.init();
    assert!(env.wallet_file().is_file());

    env.set(&["k=v"], b"secret").ok();
    let before = fs::read(env.wallet_file()).unwrap();

    let again = env.run(&["init"]).code(1);
    assert!(again.stderr.contains("already exists"), "{}", again.stderr);
    assert_eq!(fs::read(env.wallet_file()).unwrap(), before);
}

#[test]
fn init_rejects_dangerous_kdf_settings() {
    let env = Env::new();
    env.run(&["init", "--kdf-memory-mib", "0"]).code(1);
    env.run(&["init", "--kdf-iterations", "0"]).code(1);
    env.run(&["init", "--kdf-iterations", "1000"]).code(1);
    env.run(&["init", "--kdf-memory-mib", "4294967295"]).code(1);
    assert!(!env.wallet_file().exists());
}

#[test]
fn init_rejects_an_empty_password() {
    let env = Env::new();
    fs::write(&env.password_file, "\n").unwrap();
    let out = env.run(&["init"]).code(1);
    assert!(out.stderr.contains("empty"), "{}", out.stderr);
    assert!(!env.wallet_file().exists());
}

#[cfg(unix)]
#[test]
fn a_fresh_directory_and_wallet_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    env.init();
    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&env.dir), 0o700);
    assert_eq!(mode(&env.wallet_file()), 0o600);
}

// ---- set / get -------------------------------------------------------------

#[test]
fn secrets_roundtrip_byte_for_byte_including_binary() {
    let env = Env::new();
    env.init();
    let mut secret: Vec<u8> = (0..=255u8).collect();
    secret.extend_from_slice(b"\n\r\n\0trailing newline\n");
    env.set(&["service=blob"], &secret).ok();

    let got = env.get(&["service=blob"]).ok();
    assert_eq!(got.stdout, secret, "get must emit exactly what set stored");
}

#[test]
fn get_adds_no_trailing_newline_when_piped() {
    let env = Env::new();
    env.init();
    env.set(&["k=v"], b"abc").ok();
    assert_eq!(env.get(&["k=v"]).ok().stdout, b"abc");
}

#[test]
fn strip_newline_removes_exactly_one_trailing_newline() {
    let env = Env::new();
    env.init();

    env.set(&["k=raw"], b"pw\n").ok();
    assert_eq!(env.get(&["k=raw"]).ok().stdout, b"pw\n", "default is exact");

    env.run_with_stdin(&["set", "--strip-newline", "k=lf"], b"pw\n")
        .ok();
    assert_eq!(env.get(&["k=lf"]).ok().stdout, b"pw");

    env.run_with_stdin(&["set", "--strip-newline", "k=crlf"], b"pw\r\n")
        .ok();
    assert_eq!(env.get(&["k=crlf"]).ok().stdout, b"pw");

    env.run_with_stdin(&["set", "--strip-newline", "k=two"], b"pw\n\n")
        .ok();
    assert_eq!(env.get(&["k=two"]).ok().stdout, b"pw\n");
}

#[test]
fn set_replaces_an_item_with_identical_attributes() {
    let env = Env::new();
    env.init();
    env.set(&["service=gh", "user=ann"], b"old").ok();
    env.set(&["user=ann", "service=gh"], b"new").ok(); // order is irrelevant

    assert_eq!(env.get(&["service=gh"]).ok().stdout, b"new");
    let list: serde_json::Value =
        serde_json::from_str(&env.run(&["list", "--json"]).ok().stdout_str()).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[test]
fn no_replace_adds_a_second_item() {
    let env = Env::new();
    env.init();
    env.set(&["k=v"], b"one").ok();
    env.run_with_stdin(&["set", "--no-replace", "k=v"], b"two")
        .ok();

    let list: serde_json::Value =
        serde_json::from_str(&env.run(&["list", "--json"]).ok().stdout_str()).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 2);
}

#[test]
fn an_empty_secret_is_refused_and_does_not_clobber_the_old_one() {
    let env = Env::new();
    env.init();
    env.set(&["k=v"], b"precious").ok();
    let out = env.set(&["k=v"], b"").code(1);
    assert!(out.stderr.contains("empty"), "{}", out.stderr);
    assert_eq!(env.get(&["k=v"]).ok().stdout, b"precious");
}

#[test]
fn label_and_content_type_are_stored() {
    let env = Env::new();
    env.init();
    env.run_with_stdin(
        &[
            "set",
            "--label",
            "My Token",
            "--content-type",
            "application/x-token",
            "k=v",
        ],
        b"s",
    )
    .ok();
    let list: serde_json::Value =
        serde_json::from_str(&env.run(&["list", "--json"]).ok().stdout_str()).unwrap();
    assert_eq!(list[0]["label"], "My Token");
    assert_eq!(list[0]["content_type"], "application/x-token");
}

#[test]
fn default_label_is_the_attribute_values() {
    let env = Env::new();
    env.init();
    env.set(&["service=gitlab", "user=ann"], b"s").ok();
    let list: serde_json::Value =
        serde_json::from_str(&env.run(&["list", "--json"]).ok().stdout_str()).unwrap();
    assert_eq!(list[0]["label"], "gitlab ann");
}

#[test]
fn get_distinguishes_missing_ambiguous_and_by_id() {
    let env = Env::new();
    env.init();
    env.set(&["service=gh", "user=ann"], b"ann-secret").ok();
    env.set(&["service=gh", "user=bob"], b"bob-secret").ok();

    env.get(&["service=nope"]).code(3);

    let ambiguous = env.get(&["service=gh"]).code(1);
    assert!(
        ambiguous.stderr.contains("2 items match"),
        "{}",
        ambiguous.stderr
    );
    assert!(
        ambiguous.stdout.is_empty(),
        "nothing may be printed when ambiguous"
    );
    assert!(
        !ambiguous.stderr.contains("secret"),
        "the listing must not reveal secrets"
    );

    // --first picks deterministically (labels sort "gh ann" < "gh bob").
    assert_eq!(
        env.run(&["get", "--first", "service=gh"]).ok().stdout,
        b"ann-secret"
    );

    // By id prefix.
    let list: serde_json::Value =
        serde_json::from_str(&env.run(&["list", "--json"]).ok().stdout_str()).unwrap();
    let bob_id = list
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["attributes"]["user"] == "bob")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        env.run(&["get", "--id", &bob_id[..8]]).ok().stdout,
        b"bob-secret"
    );
    env.run(&["get", "--id", "ffffffffffff"]).code(3);
}

// ---- list ------------------------------------------------------------------

#[test]
fn list_never_reveals_secrets() {
    let env = Env::new();
    env.init();
    env.set(&["k=v"], b"top-secret-value-1234").ok();

    for args in [&["list"][..], &["list", "--json"], &["list", "k=v"]] {
        let out = env.run(args).ok();
        let text = out.stdout_str();
        assert!(!text.contains("top-secret"), "{args:?} leaked: {text}");
        // ...nor its base64 form
        assert!(
            !text.contains("dG9wLXNlY3JldC12YWx1ZS0xMjM0"),
            "{args:?} leaked base64"
        );
    }
}

#[test]
fn list_filters_by_attributes_and_prints_a_table() {
    let env = Env::new();
    env.init();
    env.set(&["service=gh", "user=ann"], b"1").ok();
    env.set(&["service=gl", "user=ann"], b"2").ok();

    let all = env.run(&["list"]).ok().stdout_str();
    assert!(all.starts_with("ID "), "{all}");
    assert!(all.contains("LABEL") && all.contains("ATTRIBUTES") && all.contains("MODIFIED"));
    assert!(all.contains("service=gh user=ann") && all.contains("service=gl user=ann"));

    let one = env.run(&["list", "service=gl"]).ok().stdout_str();
    assert!(
        one.contains("service=gl") && !one.contains("service=gh"),
        "{one}"
    );

    // No match is not an error, and prints nothing when captured.
    let none = env.run(&["list", "service=zzz"]).ok();
    assert!(none.stdout.is_empty());
    // `ls` and `search` are aliases.
    assert_eq!(env.run(&["ls"]).ok().stdout, env.run(&["list"]).ok().stdout);
    env.run(&["search", "service=gl"]).ok();
}

#[test]
fn list_json_has_expected_shape_and_valid_timestamps() {
    let env = Env::new();
    env.init();
    env.set(&["k=v"], b"12345").ok();
    let v: serde_json::Value =
        serde_json::from_str(&env.run(&["list", "--json"]).ok().stdout_str()).unwrap();
    let item = &v[0];
    assert_eq!(item["id"].as_str().unwrap().len(), 32);
    assert_eq!(item["secret_bytes"], 5);
    assert_eq!(item["attributes"]["k"], "v");
    let created = item["created_at"].as_str().unwrap();
    assert!(created.ends_with('Z') && created.len() == 20, "{created}");
    assert!(created.starts_with("20"), "{created}");
    assert!(item.get("secret").is_none());
}

#[test]
fn control_characters_in_labels_cannot_reach_the_terminal() {
    let env = Env::new();
    env.init();
    env.run_with_stdin(&["set", "--label", "evil\x1b[2J\x07label", "k=v"], b"s")
        .ok();
    let table = env.run(&["list"]).ok().stdout_str();
    assert!(
        !table.contains('\x1b') && !table.contains('\x07'),
        "{table:?}"
    );
    // JSON escapes control characters itself.
    let json = env.run(&["list", "--json"]).ok().stdout_str();
    assert!(!json.contains('\x1b'), "{json:?}");
}

// ---- rm --------------------------------------------------------------------

#[test]
fn rm_by_attributes_by_id_and_all() {
    let env = Env::new();
    env.init();
    env.set(&["svc=a", "n=1"], b"1").ok();
    env.set(&["svc=a", "n=2"], b"2").ok();
    env.set(&["svc=b", "n=3"], b"3").ok();

    // Unique match: removed.
    env.run(&["rm", "n=3"]).ok();
    env.get(&["n=3"]).code(3);

    // Ambiguous match: refuses and deletes nothing.
    let refused = env.run(&["rm", "svc=a"]).code(1);
    assert!(
        refused.stderr.contains("2 items match"),
        "{}",
        refused.stderr
    );
    assert!(refused.stderr.contains("--all"));
    env.get(&["n=1"]).ok();
    env.get(&["n=2"]).ok();

    // --all removes both.
    env.run(&["rm", "--all", "svc=a"]).ok();
    env.get(&["n=1"]).code(3);
    env.get(&["n=2"]).code(3);

    // Nothing left to remove.
    env.run(&["rm", "svc=a"]).code(3);

    // By id.
    env.set(&["x=y"], b"z").ok();
    let v: serde_json::Value =
        serde_json::from_str(&env.run(&["list", "--json"]).ok().stdout_str()).unwrap();
    let id = v[0]["id"].as_str().unwrap().to_owned();
    env.run(&["rm", "--id", &id[..10]]).ok();
    env.run(&["rm", "--id", &id]).code(3);
    assert!(env.run(&["list"]).ok().stdout.is_empty());
}

#[test]
fn rm_alias_delete_works() {
    let env = Env::new();
    env.init();
    env.set(&["k=v"], b"s").ok();
    env.run(&["delete", "k=v"]).ok();
    env.get(&["k=v"]).code(3);
}

// ---- passwords -------------------------------------------------------------

#[test]
fn wrong_password_exits_4_and_changes_nothing() {
    let env = Env::new();
    env.init();
    env.set(&["k=v"], b"s").ok();
    let before = fs::read(env.wallet_file()).unwrap();

    fs::write(&env.password_file, "not the password\n").unwrap();
    let out = env.get(&["k=v"]).code(4);
    assert!(out.stdout.is_empty());
    env.set(&["k=other"], b"x").code(4);
    env.run(&["rm", "k=v"]).code(4);
    assert_eq!(fs::read(env.wallet_file()).unwrap(), before);
}

#[test]
fn password_files_may_end_in_lf_or_crlf_or_nothing() {
    let env = Env::new();
    env.init(); // created with "...\n"
    env.set(&["k=v"], b"s").ok();
    for content in [format!("{PASSWORD}\r\n"), PASSWORD.to_owned()] {
        fs::write(&env.password_file, content).unwrap();
        assert_eq!(env.get(&["k=v"]).ok().stdout, b"s");
    }
}

#[test]
fn a_non_utf8_password_file_is_an_error() {
    let env = Env::new();
    env.init();
    fs::write(&env.password_file, [0xff, 0xfe, 0xfd]).unwrap();
    let out = env.get(&["k=v"]).code(1);
    assert!(out.stderr.contains("UTF-8"), "{}", out.stderr);
}

#[test]
fn a_missing_password_file_is_an_error() {
    let env = Env::new();
    env.init();
    let mut cmd = env.command(&["get", "k=v"]);
    cmd.env("SESAME_PASSWORD_FILE", env.dir.join("does-not-exist"));
    let out = exec(cmd, None).code(1);
    assert!(out.stderr.contains("password file"), "{}", out.stderr);
}

#[test]
fn password_can_come_from_stdin() {
    let env = Env::new();
    env.init();
    env.set(&["k=v"], b"s").ok();

    let mut cmd = env.command(&["--password-stdin", "get", "k=v"]);
    cmd.env_remove("SESAME_PASSWORD_FILE");
    let out = exec(cmd, Some(format!("{PASSWORD}\n").as_bytes())).ok();
    assert_eq!(out.stdout, b"s");
}

#[test]
fn password_file_option_overrides_nothing_but_conflicts_with_stdin() {
    let env = Env::new();
    env.init();
    let mut cmd = env.command(&["--password-stdin", "get", "k=v"]);
    cmd.env("SESAME_PASSWORD_FILE", &env.password_file);
    let out = exec(cmd, Some(b"x")).code(2);
    assert!(
        out.stderr.contains("cannot be used together"),
        "{}",
        out.stderr
    );
}

#[test]
fn set_cannot_take_both_password_and_secret_from_stdin() {
    let env = Env::new();
    env.init();
    let mut cmd = env.command(&["--password-stdin", "set", "k=v"]);
    cmd.env_remove("SESAME_PASSWORD_FILE");
    let out = exec(cmd, Some(b"x")).code(2);
    assert!(out.stderr.contains("--password-file"), "{}", out.stderr);
}

#[test]
fn passwd_changes_the_password_and_keeps_the_items() {
    let env = Env::new();
    env.init();
    env.set(&["k=1"], b"one").ok();
    env.set(&["k=2"], b"two").ok();

    let new_pw = env.dir.join("new-password");
    fs::write(&new_pw, "a different password\n").unwrap();
    env.run(&["passwd", "--new-password-file", new_pw.to_str().unwrap()])
        .ok();

    // The old password no longer opens it.
    env.get(&["k=1"]).code(4);

    // The new one does, with everything intact.
    let mut cmd = env.command(&["get", "k=2"]);
    cmd.env("SESAME_PASSWORD_FILE", &new_pw);
    assert_eq!(exec(cmd, None).ok().stdout, b"two");
}

#[test]
fn passwd_can_raise_the_kdf_cost_and_keeps_it_when_not_told() {
    let env = Env::new();
    env.init(); // 1 MiB, 1 pass
    let header = |env: &Env| fs::read(env.wallet_file()).unwrap();
    let kdf = |bytes: &[u8]| {
        (
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        )
    };
    assert_eq!(kdf(&header(&env)), (1024, 1));

    let same = env.dir.join("same");
    fs::write(&same, format!("{PASSWORD}\n")).unwrap();
    env.run(&["passwd", "--new-password-file", same.to_str().unwrap()])
        .ok();
    assert_eq!(
        kdf(&header(&env)),
        (1024, 1),
        "unspecified cost is preserved"
    );

    env.run(&[
        "passwd",
        "--new-password-file",
        same.to_str().unwrap(),
        "--kdf-memory-mib",
        "2",
        "--kdf-iterations",
        "2",
    ])
    .ok();
    assert_eq!(kdf(&header(&env)), (2048, 2));
    env.run(&["list"]).ok();
}

// ---- wallets ---------------------------------------------------------------

#[test]
fn wallets_are_independent_and_listed() {
    let env = Env::new();
    env.init();
    let mut args = vec!["-w", "work", "init"];
    args.extend(FAST_KDF);
    env.run(&args).ok();

    env.set(&["k=v"], b"personal").ok();
    env.run_with_stdin(&["-w", "work", "set", "k=v"], b"work")
        .ok();

    assert_eq!(env.get(&["k=v"]).ok().stdout, b"personal");
    assert_eq!(env.run(&["-w", "work", "get", "k=v"]).ok().stdout, b"work");
    assert_eq!(env.run(&["wallets"]).ok().stdout_str(), "default\nwork\n");
}

#[test]
fn wallet_can_be_selected_by_environment_variable() {
    let env = Env::new();
    let mut args = vec!["-w", "viaenv", "init"];
    args.extend(FAST_KDF);
    env.run(&args).ok();

    let mut cmd = env.command(&["path"]);
    cmd.env("SESAME_WALLET", "viaenv");
    let out = exec(cmd, None).ok().stdout_str();
    assert!(out.trim_end().ends_with("viaenv.sesame"), "{out}");
}

#[test]
fn a_missing_wallet_exits_3_with_a_hint() {
    let env = Env::new();
    let out = env.get(&["k=v"]).code(3);
    assert!(out.stderr.contains("sesame init"), "{}", out.stderr);
    env.run(&["-w", "typo", "list"]).code(3);
    assert!(!env.dir.exists(), "probing must not create the directory");
}

#[test]
fn unsafe_wallet_names_are_rejected() {
    let env = Env::new();
    for name in ["../escape", "a/b", "Upper", ".hidden", "con", ""] {
        let out = env.run(&["-w", name, "init"]);
        assert_eq!(out.code, 1, "{name:?}: {}", out.stderr);
        assert!(
            out.stderr.contains("invalid wallet name"),
            "{name:?}: {}",
            out.stderr
        );
    }
    assert!(!env.dir.exists());
}

#[test]
fn wallets_in_an_empty_directory_lists_nothing() {
    let env = Env::new();
    assert!(env.run(&["wallets"]).ok().stdout.is_empty());
}

#[test]
fn path_prints_the_wallet_file_location() {
    let env = Env::new();
    let out = env.run(&["path"]).ok().stdout_str();
    assert_eq!(PathBuf::from(out.trim_end()), env.wallet_file());
}

#[cfg(unix)]
#[test]
fn default_location_is_the_per_user_data_directory() {
    let home = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(BIN);
    cmd.arg("path")
        .env_remove("SESAME_DIR")
        .env_remove("SESAME_WALLET")
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path().join("xdg"))
        .stdin(Stdio::null());
    let out = exec(cmd, None).ok().stdout_str();
    let path = PathBuf::from(out.trim_end());
    assert!(path.starts_with(home.path()), "{path:?}");
    let tail: Vec<_> = path.components().rev().take(2).collect();
    assert_eq!(tail[0].as_os_str(), "default.sesame");
    assert_eq!(tail[1].as_os_str(), "sesame");
}

// ---- corruption ------------------------------------------------------------

#[test]
fn a_tampered_wallet_is_reported_not_silently_accepted() {
    let env = Env::new();
    env.init();
    env.set(&["k=v"], b"s").ok();
    let mut bytes = fs::read(env.wallet_file()).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(env.wallet_file(), bytes).unwrap();
    let out = env.get(&["k=v"]).code(4);
    assert!(out.stderr.contains("corrupt"), "{}", out.stderr);
}

#[test]
fn a_file_that_is_not_a_wallet_is_reported() {
    let env = Env::new();
    fs::create_dir_all(&env.dir).unwrap();
    fs::write(env.wallet_file(), vec![b'x'; 200]).unwrap();
    let out = env.get(&["k=v"]).code(1);
    assert!(out.stderr.contains("not a sesame wallet"), "{}", out.stderr);
}

// ---- usage -----------------------------------------------------------------

#[test]
fn usage_errors_exit_2_and_never_echo_the_offending_argument() {
    let env = Env::new();
    env.init();

    // Someone types a secret where ATTR=VALUE belongs.
    for args in [
        &["get", "hunter2-oops"][..],
        &["rm", "hunter2-oops"],
        &["list", "hunter2-oops"],
        &["set", "hunter2-oops"],
    ] {
        let out = env.run_with_stdin(args, b"x").code(2);
        assert!(
            !out.stderr.contains("hunter2-oops"),
            "{args:?}: {}",
            out.stderr
        );
        assert!(
            out.stderr.contains("ATTR=VALUE"),
            "{args:?}: {}",
            out.stderr
        );
    }

    env.run(&["get"]).code(2);
    env.run(&["rm"]).code(2);
    env.run(&["get", "--id", "ab", "k=v"]).code(2); // --id and attributes conflict
    env.run(&["get", "k=1", "k=2"]).code(2); // duplicate attribute
    env.run(&["get", "=v"]).code(2); // empty name
    env.run(&["nonsense"]).code(2);
    env.run(&["set"]).code(2); // set needs attributes
}

#[test]
fn help_and_version_work_and_document_exit_codes() {
    let env = Env::new();
    let help = env.run(&["--help"]).ok().stdout_str();
    assert!(help.contains("EXIT STATUS") && help.contains("wrong password"));
    assert!(help.contains("PASSWORDS") && help.contains("FILES"));
    let version = env.run(&["--version"]).ok().stdout_str();
    assert!(version.starts_with("sesame "), "{version}");
    for sub in [
        "init", "set", "get", "list", "rm", "passwd", "wallets", "path",
    ] {
        env.run(&[sub, "--help"]).ok();
    }
}

#[test]
fn password_file_path_is_not_shown_in_help() {
    let env = Env::new();
    let mut cmd = env.command(&["--help"]);
    cmd.env("SESAME_PASSWORD_FILE", "/very/distinctive/path");
    let help = exec(cmd, None).ok().stdout_str();
    assert!(!help.contains("distinctive"), "{help}");
}

// ---- concurrency ------------------------------------------------------------

/// The reason the file lock exists: many `sesame` processes writing at once.
#[test]
fn simultaneous_processes_do_not_lose_updates() {
    const N: usize = 12;
    let env = Env::new();
    env.init();

    let children: Vec<_> = (0..N)
        .map(|i| {
            let mut cmd = env.command(&["set", &format!("n={i}")]);
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = cmd.spawn().unwrap();
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(format!("secret-{i}").as_bytes()).unwrap();
            drop(stdin);
            child
        })
        .collect();

    for (i, child) in children.into_iter().enumerate() {
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "writer {i} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let list: serde_json::Value =
        serde_json::from_str(&env.run(&["list", "--json"]).ok().stdout_str()).unwrap();
    assert_eq!(list.as_array().unwrap().len(), N, "an update was lost");
    for i in 0..N {
        assert_eq!(
            env.get(&[&format!("n={i}")]).ok().stdout,
            format!("secret-{i}").as_bytes()
        );
    }
}
