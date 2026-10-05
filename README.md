# sesame

A **rootless, daemonless** secret store: the job of KWallet or gnome-keyring,
without the service.

- **Daemonless.** A wallet is one encrypted file. There is no background process,
  no D-Bus service and no socket. Every command locks the file, decrypts it, does
  its work, atomically writes it back and exits. Any number of processes can use
  a wallet at the same time; a file lock serialises them.
- **Rootless.** Everything lives in per-user directories with owner-only
  permissions. Nothing is installed system-wide and nothing runs with elevated
  privileges.
- **Portable.** Pure Rust: no C code to compile and no libraries to install, so
  cross-compiling needs nothing but the Rust target. Built for macOS (aarch64),
  Linux (aarch64, x86_64) and Windows (aarch64, x86_64). The
  wallet format is identical everywhere, so a wallet file can be copied or synced
  between machines and operating systems.

```console
$ sesame init
$ printf '%s' "$GITHUB_TOKEN" | sesame set --label "GitHub token" service=github user=ann
$ sesame get service=github user=ann
ghp_...
$ sesame list
ID        LABEL         ATTRIBUTES               MODIFIED
647120ae  GitHub token  service=github user=ann  2026-10-05T15:28:09Z
```

## How it differs from KWallet and gnome-keyring

| | KWallet / gnome-keyring | sesame |
|---|---|---|
| Process model | resident daemon, started with your session | none: a library call or a short-lived command |
| Unlocked state | held in the daemon's memory between requests | never held: each command asks for the password |
| Storage | per-user files managed by the daemon | one file per wallet, managed by you |
| Interface | D-Bus (Secret Service / KWallet API) | CLI and Rust library |
| Desktop integration | PAM auto-unlock, GUI managers | none |
| Platforms | Linux desktops | macOS, Linux, Windows |

The trade-off is deliberate and worth being clear about. With no daemon there is
no unlocked secret sitting in a long-lived process, and nothing to start, supervise
or attack over IPC. A locked wallet is a file. The price is that **sesame does not
speak the Secret Service D-Bus API**, so applications that talk to libsecret
(browsers, many GUI tools) can't use it, and **nothing is cached between
commands**, so each one asks for the password and pays for one key derivation
(roughly a tenth of a second at the default cost).

## Install

```console
$ cargo install --path .        # needs Rust 1.89 or newer
```

sesame is not published to crates.io yet. To use only the library, without the
CLI's dependencies, point at a checkout:

```toml
sesame = { path = "../sesame", default-features = false }
```

## Using the CLI

Items are found by **attributes** (`key=value` pairs), as with the Secret Service
API and `secret-tool`, not by name.

| Command | Does |
|---|---|
| `sesame init` | create a wallet |
| `sesame set ATTR=VALUE...` | store a secret (also `store`) |
| `sesame get ATTR=VALUE...` | print a secret (also `lookup`) |
| `sesame list [ATTR=VALUE...]` | list items, never secrets (also `ls`, `search`) |
| `sesame rm ATTR=VALUE...` | delete items (also `delete`) |
| `sesame passwd` | change the password |
| `sesame wallets` / `sesame path` | list wallets / show the wallet file's path |

Things worth knowing:

- **`set`** reads the secret from stdin, byte for byte (use `printf`/`echo -n`, or
  `--strip-newline`), or prompts for it, hidden and confirmed, on a terminal.
  Secrets are never accepted as arguments, where other users could see them in the
  process list. Storing an item whose attributes exactly match an existing one
  updates it in place, so `set` is idempotent. An empty secret is refused, so a
  failed upstream command can't overwrite a good secret with nothing.
- **`get`** prints the raw secret with no trailing newline (one is added on a
  terminal). If several items match it lists them and fails; narrow the query, use
  `--id`, or pass `--first`.
- **`rm`** with several matches refuses unless you pass `--all`.
- **`--id`** accepts any unambiguous prefix of the id shown by `list`.
- **Several wallets:** `-w work` (or `SESAME_WALLET`). Names are lowercase
  `a-z 0-9 - _ .`, so a wallet directory can't have case collisions when copied
  between systems.

### Scripting

```console
$ export SESAME_PASSWORD_FILE=~/.config/sesame-pw    # or --password-stdin
$ token=$(sesame get service=github user=ann) || echo "exit status $?"
```

| Exit status | Meaning |
|---|---|
| 0 | success |
| 1 | failure |
| 2 | usage error |
| 3 | wallet or item not found |
| 4 | wrong password (or corrupted wallet) |

Environment: `SESAME_DIR`, `SESAME_WALLET`, `SESAME_PASSWORD_FILE`. Informational
messages are printed only when stderr is a terminal, so captured output contains
just the data you asked for. Keeping a password in a file trades security for
convenience; prefer the interactive prompt where you can.

### Where wallets live

A wallet is `<dir>/<name>.sesame`, with the directory (created `0700` on unix):

| Platform | Default directory |
|---|---|
| Linux | `$XDG_DATA_HOME/sesame` (`~/.local/share/sesame`) |
| macOS | `~/Library/Application Support/sesame` |
| Windows | `%LOCALAPPDATA%\sesame` (local, not roaming) |

Override with `--dir` / `SESAME_DIR`. **Backup is `cp`.** A symlinked wallet file is
followed on save, so keeping it in a synced folder works.

## Using the library

```rust
use sesame::{Attributes, KdfParams, NewItem, Wallet};

let wallet = Wallet::create("demo.sesame", "correct horse", KdfParams::default())?;
wallet.put(
    NewItem::new("GitHub token", "ghp_...").attribute("service", "github"),
    true, // replace an existing item with the same attributes
)?;

let mut query = Attributes::new();
query.insert("service".into(), "github".into());
let hits = wallet.search(&query)?;
assert_eq!(hits[0].secret.expose(), b"ghp_...");
```

A `Wallet` is the derived key plus a path, not a connection. Every method is a
self-contained locked transaction on the file, so handles in any number of threads
or processes never lose each other's updates. `Wallet::update` runs a closure under
one exclusive lock for multi-step changes. `Secret` is zeroized on drop and its
`Debug` is redacted; `Item` and `Vault` deliberately do not implement `Serialize`.

## Security design

- **Key derivation:** Argon2id (v1.3) over the NFC-normalised password, 32-byte
  random salt. Default cost 64 MiB, 3 passes, 1 lane (RFC 9106's second
  recommendation), stored in the header and raisable with
  `sesame passwd --kdf-memory-mib N --kdf-iterations N`.
- **Encryption:** XChaCha20-Poly1305 over the whole payload with a fresh random
  192-bit nonce on every save. The 77-byte header is authenticated as associated
  data, so changing any byte of the file, including the KDF settings, fails
  authentication.
- **Everything is encrypted**, labels and attributes included. The file reveals
  only the KDF cost and its approximate size.
- **Safe replacement:** saves write a temporary file, `fsync`, then atomically
  rename over the wallet, so readers and crashes see the old or the new wallet,
  never a torn one. Locking uses a sidecar `.lock` file (a lock on the wallet
  itself wouldn't survive being replaced).
- **Hostile files:** KDF parameters are bounded before use (at most 1 GiB, 64
  passes), and files over 64 MiB are refused.
- **Memory hygiene:** keys, passwords, secrets and Argon2's working memory are
  wiped on drop; the CLI disables core dumps (unix) and, on Linux, marks the
  process non-dumpable. This is best-effort.

The byte-level format is specified in the docs of [`src/format.rs`](src/format.rs).

**What sesame does not protect against:** malware running as you; a debugger or
memory dump of a live process (or swap); a weak password, since the wallet file is
open to offline guessing by anyone who can read it, which is what Argon2 slows but
cannot prevent; **rollback**, since an attacker who can write the file can restore
an older valid copy and authenticated encryption cannot tell the difference. There
is **no password recovery**.

Other limits: file locking needs a filesystem with working advisory locks (some
network filesystems don't have them); on Windows, files rely on the inherited
ACL of `%LOCALAPPDATA%`, which is private to your user, SYSTEM and Administrators;
and a process killed mid-save can leave a stray `.<name>.<random>.tmp` file, which
is ciphertext and safe to delete.

## Platform support

| Platform | Architecture | Rust target |
|---|---|---|
| macOS | aarch64 | `aarch64-apple-darwin` |
| Linux | x86_64 | `x86_64-unknown-linux-gnu` |
| Linux | aarch64 | `aarch64-unknown-linux-gnu` |
| Windows | x86_64 | `x86_64-pc-windows-msvc` |
| Windows | aarch64 | `aarch64-pc-windows-msvc` |

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) builds and runs the whole
test suite natively on a runner of each architecture, plus fmt, clippy on all three
operating systems, and a check against the minimum Rust version. A checked-in
golden wallet (`tests/data/golden-v1.sesame`) is opened on every platform, which is
what backs the claim that one file works everywhere. The musl Linux targets
also pass `cargo clippy`, but are not linked or run by CI.

## Development

```console
$ cargo test                      # unit, library integration, CLI, doc tests
$ cargo clippy --all-targets -- -D warnings
```

The test suite includes cross-process concurrency tests that spawn real `sesame`
processes. Interactive prompting needs a terminal and isn't covered by `cargo test`.

## License

Apache-2.0. See [LICENSE](LICENSE).
