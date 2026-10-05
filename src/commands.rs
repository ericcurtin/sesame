//! The implementation of each subcommand.

use std::{
    io::{self, IsTerminal, Write},
    path::Path,
};

use sesame::{Attributes, Error, Item, KdfParams, NewItem, Store, Wallet};

use crate::{
    args::{Cli, Command, GetArgs, InitArgs, KdfArgs, ListArgs, PasswdArgs, RmArgs, SetArgs},
    failure::CliError,
    prompt::{self, PasswordSource},
    timefmt::rfc3339_utc,
};

type Outcome = Result<(), CliError>;

/// Everything every command needs to know.
struct Ctx {
    store: Store,
    wallet: String,
    password: PasswordSource,
}

pub fn run(cli: Cli) -> Outcome {
    let dir = match cli.dir {
        Some(dir) => dir,
        None => sesame::default_dir()?,
    };
    let ctx = Ctx {
        store: Store::new(dir),
        wallet: cli.wallet,
        password: PasswordSource::from_args(cli.password_file, cli.password_stdin)?,
    };

    match cli.command {
        Command::Init(a) => init(&ctx, a),
        Command::Set(a) => set(&ctx, a),
        Command::Get(a) => get(&ctx, a),
        Command::List(a) => list(&ctx, a),
        Command::Rm(a) => rm(&ctx, a),
        Command::Passwd(a) => passwd(&ctx, a),
        Command::Wallets => wallets(&ctx),
        Command::Path => path(&ctx),
    }
}

// ---- helpers ---------------------------------------------------------------

/// Print an informational message, but only to a human.
///
/// Successful commands are silent when their output is captured, so scripts
/// and pipelines see nothing but the data they asked for.
fn note(message: impl AsRef<str>) {
    if io::stderr().is_terminal() {
        eprintln!("{}", message.as_ref());
    }
}

/// Write to stdout, treating a closed pipe (`sesame list | head`) as success.
fn write_stdout(bytes: &[u8]) -> Outcome {
    let mut out = io::stdout().lock();
    match out.write_all(bytes).and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(CliError::Failure(format!("cannot write to stdout: {e}"))),
    }
}

/// Make untrusted text (labels, attribute values) safe to show on a terminal:
/// control characters, including escape sequences and newlines, become `?`.
fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// First eight characters of an item id: enough to identify an item, and
/// accepted anywhere an `--id` is.
fn short_id(id: &str) -> &str {
    &id[..id.len().min(8)]
}

/// Parse `ATTR=VALUE` arguments. Error messages never echo the argument, which
/// might be a secret typed in the wrong place.
fn parse_attributes(args: &[String]) -> Result<Attributes, CliError> {
    let mut attributes = Attributes::new();
    for (n, arg) in args.iter().enumerate() {
        let Some((key, value)) = arg.split_once('=') else {
            return Err(CliError::Usage(format!(
                "argument {} is not in ATTR=VALUE form",
                n + 1
            )));
        };
        if key.is_empty() {
            return Err(CliError::Usage(format!(
                "argument {} has an empty attribute name",
                n + 1
            )));
        }
        if attributes
            .insert(key.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(CliError::Usage(format!(
                "attribute {key:?} was given more than once"
            )));
        }
    }
    sesame::validate_attributes(&attributes)?;
    Ok(attributes)
}

/// How a command picks items: by id, or by attributes.
enum Selector {
    Id(String),
    Attributes(Attributes),
}

impl Selector {
    fn from_args(id: Option<String>, attributes: &[String]) -> Result<Self, CliError> {
        match id {
            Some(id) => Ok(Selector::Id(id)),
            None if attributes.is_empty() => Err(CliError::Usage(
                "specify what to select: ATTR=VALUE arguments or --id ID".into(),
            )),
            None => Ok(Selector::Attributes(parse_attributes(attributes)?)),
        }
    }
}

fn kdf_params(args: &KdfArgs, base: KdfParams) -> Result<KdfParams, CliError> {
    let memory_kib = match args.kdf_memory_mib {
        Some(mib) => mib
            .checked_mul(1024)
            .ok_or_else(|| CliError::Failure("--kdf-memory-mib is too large".into()))?,
        None => base.memory_kib(),
    };
    let iterations = args.kdf_iterations.unwrap_or(base.iterations());
    Ok(KdfParams::new(memory_kib, iterations, base.parallelism())?)
}

/// Unlock the selected wallet.
///
/// Existence is checked before the password is asked for, so a typo in the
/// wallet name doesn't make the user type a password for nothing.
fn open(ctx: &Ctx) -> Result<Wallet, CliError> {
    let path = ctx.store.wallet_path(&ctx.wallet)?;
    if !path
        .try_exists()
        .map_err(|e| CliError::Failure(format!("cannot access {}: {e}", path.display())))?
    {
        return Err(not_found(&ctx.wallet, &path));
    }
    let password = ctx.password.existing(&ctx.wallet)?;
    Wallet::open(&path, &password).map_err(|e| match e {
        Error::WalletNotFound(p) => not_found(&ctx.wallet, &p),
        other => other.into(),
    })
}

fn not_found(name: &str, path: &Path) -> CliError {
    CliError::NotFound(format!(
        "wallet {name:?} does not exist ({}); create it with `sesame init`",
        path.display()
    ))
}

fn item_error(e: Error) -> CliError {
    match e {
        Error::ItemNotFound => CliError::NotFound("no matching item".into()),
        Error::AmbiguousId => CliError::Failure(
            "that id prefix matches more than one item; use more characters".into(),
        ),
        other => other.into(),
    }
}

/// A listing of items for an "N items match" message.
fn describe_matches(items: &[&Item]) -> String {
    items
        .iter()
        .map(|i| format!("  {}  {}", short_id(&i.id), sanitize(&i.label)))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---- commands --------------------------------------------------------------

fn init(ctx: &Ctx, args: InitArgs) -> Outcome {
    let path = ctx.store.wallet_path(&ctx.wallet)?;
    let kdf = kdf_params(&args.kdf, KdfParams::DEFAULT)?;

    // Fail before prompting if there's nothing to create.
    if ctx.store.exists(&ctx.wallet)? {
        return Err(Error::WalletExists(path).into());
    }

    note(format!(
        "Creating wallet {:?}. There is no password recovery: if you forget it, \
         the wallet cannot be opened.",
        ctx.wallet
    ));
    let password = ctx.password.new_password(&ctx.wallet)?;
    ctx.store.create_wallet(&ctx.wallet, &password, kdf)?;
    note(format!("Created {}", path.display()));
    Ok(())
}

fn set(ctx: &Ctx, args: SetArgs) -> Outcome {
    let attributes = parse_attributes(&args.attributes)?;

    if ctx.password.uses_stdin() {
        return Err(CliError::Usage(
            "--password-stdin cannot be combined with `set`, which reads the secret from stdin; \
             use --password-file"
                .into(),
        ));
    }

    let wallet = open(ctx)?;
    let secret = prompt::read_secret(args.strip_newline)?;
    if secret.is_empty() {
        // An empty pipe usually means an upstream command failed. Storing it
        // would silently overwrite a good secret with nothing.
        return Err(CliError::Failure(
            "refusing to store an empty secret".into(),
        ));
    }

    let label = args.label.unwrap_or_else(|| {
        attributes
            .values()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    });
    let mut item = NewItem::new(label, secret).attributes(attributes);
    if let Some(content_type) = args.content_type {
        item = item.content_type(content_type);
    }

    let outcome = wallet.put(item, !args.no_replace)?;
    note(format!(
        "{} item {}",
        if outcome.replaced {
            "Updated"
        } else {
            "Stored"
        },
        short_id(&outcome.id)
    ));
    Ok(())
}

fn get(ctx: &Ctx, args: GetArgs) -> Outcome {
    let selector = Selector::from_args(args.id, &args.attributes)?;
    let wallet = open(ctx)?;

    let item = wallet.read(|vault| -> Result<Item, CliError> {
        match &selector {
            Selector::Id(id) => vault.get(id).cloned().map_err(item_error),
            Selector::Attributes(query) => {
                let hits = vault.search(query);
                match hits.as_slice() {
                    [] => Err(CliError::NotFound("no matching item".into())),
                    [only] => Ok((*only).clone()),
                    [first, ..] if args.first => Ok((*first).clone()),
                    many => Err(CliError::Failure(format!(
                        "{} items match; add attributes, use --id, or pass --first:\n{}",
                        many.len(),
                        describe_matches(many)
                    ))),
                }
            }
        }
    })??;

    let mut bytes = item.secret.expose().to_vec();
    if io::stdout().is_terminal() {
        bytes.push(b'\n');
    }
    let result = write_stdout(&bytes);
    zeroize::Zeroize::zeroize(&mut bytes);
    result
}

fn list(ctx: &Ctx, args: ListArgs) -> Outcome {
    let query = parse_attributes(&args.attributes)?;
    let wallet = open(ctx)?;
    let items = wallet.search(&query)?;

    if args.json {
        let entries: Vec<ListEntry<'_>> = items
            .iter()
            .map(|i| ListEntry {
                id: &i.id,
                label: &i.label,
                attributes: &i.attributes,
                content_type: &i.content_type,
                secret_bytes: i.secret.len(),
                created_at: rfc3339_utc(i.created_at),
                modified_at: rfc3339_utc(i.modified_at),
            })
            .collect();
        let mut text = serde_json::to_string_pretty(&entries)
            .map_err(|e| CliError::Failure(format!("cannot encode JSON: {e}")))?;
        text.push('\n');
        return write_stdout(text.as_bytes());
    }

    if items.is_empty() {
        note("No items.");
        return Ok(());
    }

    let rows: Vec<[String; 4]> = items
        .iter()
        .map(|i| {
            let attrs = i
                .attributes
                .iter()
                .map(|(k, v)| format!("{}={}", sanitize(k), sanitize(v)))
                .collect::<Vec<_>>()
                .join(" ");
            [
                short_id(&i.id).to_owned(),
                sanitize(&i.label),
                attrs,
                rfc3339_utc(i.modified_at),
            ]
        })
        .collect();
    write_stdout(render_table(["ID", "LABEL", "ATTRIBUTES", "MODIFIED"], &rows).as_bytes())
}

/// Left-aligned columns separated by two spaces; the last column is not padded.
fn render_table(header: [&str; 4], rows: &[[String; 4]]) -> String {
    let mut widths = header.map(|h| h.chars().count());
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let line = |cells: [&str; 4]| -> String {
        let mut s = String::new();
        for (n, cell) in cells.iter().enumerate() {
            s.push_str(cell);
            if n + 1 < cells.len() {
                let pad = widths[n] - cell.chars().count();
                s.extend(std::iter::repeat_n(' ', pad + 2));
            }
        }
        s.push('\n');
        s
    };
    let mut out = line(header);
    for row in rows {
        out.push_str(&line([&row[0], &row[1], &row[2], &row[3]]));
    }
    out
}

/// One item in `list --json`. A typed struct rather than ad-hoc JSON so field
/// order is stable and there is structurally no way to emit the secret.
#[derive(serde::Serialize)]
struct ListEntry<'a> {
    id: &'a str,
    label: &'a str,
    attributes: &'a Attributes,
    content_type: &'a str,
    secret_bytes: usize,
    created_at: String,
    modified_at: String,
}

enum Removal {
    Removed(usize),
    NoMatch,
    Ambiguous(String, usize),
}

fn rm(ctx: &Ctx, args: RmArgs) -> Outcome {
    let selector = Selector::from_args(args.id, &args.attributes)?;
    let wallet = open(ctx)?;

    // Match and delete under one exclusive lock, so what we count is what we
    // remove even if another process is writing concurrently.
    let removal = wallet
        .update(|vault| match &selector {
            Selector::Id(id) => {
                let id = vault.get(id)?.id.clone();
                vault.remove(&id)?;
                Ok(Removal::Removed(1))
            }
            Selector::Attributes(query) => {
                let hits = vault.search(query);
                match hits.len() {
                    0 => Ok(Removal::NoMatch),
                    n if n > 1 && !args.all => Ok(Removal::Ambiguous(describe_matches(&hits), n)),
                    _ => Ok(Removal::Removed(vault.remove_matching(query))),
                }
            }
        })
        .map_err(item_error)?;

    match removal {
        Removal::Removed(n) => {
            note(format!("Removed {n} item{}", if n == 1 { "" } else { "s" }));
            Ok(())
        }
        Removal::NoMatch => Err(CliError::NotFound("no matching item".into())),
        Removal::Ambiguous(listing, n) => Err(CliError::Failure(format!(
            "{n} items match; nothing was deleted. Add attributes, use --id, or pass --all:\n{listing}"
        ))),
    }
}

fn passwd(ctx: &Ctx, args: PasswdArgs) -> Outcome {
    let mut wallet = open(ctx)?;
    let kdf = kdf_params(&args.kdf, wallet.kdf_params())?;

    let new_password = match &args.new_password_file {
        Some(file) => prompt::from_file(file)?,
        None => prompt::new_password_prompt(&ctx.wallet)?,
    };
    wallet.change_password(&new_password, kdf)?;
    note("Password changed.");
    Ok(())
}

fn wallets(ctx: &Ctx) -> Outcome {
    let names = ctx.store.list()?;
    if names.is_empty() {
        note(format!("No wallets in {}", ctx.store.dir().display()));
        return Ok(());
    }
    let mut text = names.join("\n");
    text.push('\n');
    write_stdout(text.as_bytes())
}

fn path(ctx: &Ctx) -> Outcome {
    let path = ctx.store.wallet_path(&ctx.wallet)?;
    write_stdout(format!("{}\n", path.display()).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn attributes_parse_and_values_may_contain_equals() {
        let a = parse_attributes(&s(&["service=github", "token=a=b=c", "empty="])).unwrap();
        assert_eq!(a["service"], "github");
        assert_eq!(a["token"], "a=b=c");
        assert_eq!(a["empty"], "");
    }

    #[test]
    fn bad_attributes_are_usage_errors_that_do_not_echo_the_argument() {
        for bad in [&["hunter2"][..], &["=value"], &["a=1", "a=2"]] {
            let err = parse_attributes(&s(bad)).unwrap_err();
            assert!(matches!(err, CliError::Usage(_)), "{bad:?}");
            assert!(!err.to_string().contains("hunter2"), "{err}");
        }
    }

    #[test]
    fn sanitize_neutralises_terminal_escapes() {
        assert_eq!(sanitize("ok"), "ok");
        assert_eq!(sanitize("a\x1b[31mb\nc\td"), "a?[31mb?c?d");
        assert_eq!(sanitize("naïve ☃"), "naïve ☃");
    }

    #[test]
    fn short_ids() {
        assert_eq!(short_id("0123456789abcdef"), "01234567");
        assert_eq!(short_id("abc"), "abc");
    }

    #[test]
    fn table_rendering_aligns_by_characters() {
        let rows = vec![
            [
                "aaaaaaaa".to_owned(),
                "x".to_owned(),
                "k=v".to_owned(),
                "t1".to_owned(),
            ],
            [
                "bbbbbbbb".to_owned(),
                "naïve ☃".to_owned(),
                "a=b".to_owned(),
                "t2".to_owned(),
            ],
        ];
        let out = render_table(["ID", "LABEL", "ATTRIBUTES", "MODIFIED"], &rows);
        let lines: Vec<_> = out.lines().collect();
        assert_eq!(lines[0], "ID        LABEL    ATTRIBUTES  MODIFIED");
        assert_eq!(lines[1], "aaaaaaaa  x        k=v         t1");
        assert_eq!(lines[2], "bbbbbbbb  naïve ☃  a=b         t2");
    }

    #[test]
    fn kdf_option_resolution() {
        let none = KdfArgs {
            kdf_memory_mib: None,
            kdf_iterations: None,
        };
        assert_eq!(
            kdf_params(&none, KdfParams::DEFAULT).unwrap(),
            KdfParams::DEFAULT
        );

        let some = KdfArgs {
            kdf_memory_mib: Some(1),
            kdf_iterations: Some(2),
        };
        let p = kdf_params(&some, KdfParams::DEFAULT).unwrap();
        assert_eq!(
            (p.memory_kib(), p.iterations(), p.parallelism()),
            (1024, 2, 1)
        );

        let huge = KdfArgs {
            kdf_memory_mib: Some(u32::MAX),
            kdf_iterations: None,
        };
        assert!(kdf_params(&huge, KdfParams::DEFAULT).is_err());
        let zero = KdfArgs {
            kdf_memory_mib: Some(0),
            kdf_iterations: None,
        };
        assert!(kdf_params(&zero, KdfParams::DEFAULT).is_err());
    }

    #[test]
    fn selector_requires_something() {
        assert!(matches!(
            Selector::from_args(None, &[]),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            Selector::from_args(Some("ab".into()), &[]),
            Ok(Selector::Id(_))
        ));
        assert!(matches!(
            Selector::from_args(None, &s(&["k=v"])),
            Ok(Selector::Attributes(_))
        ));
    }
}
