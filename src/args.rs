//! Command-line definition.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

const AFTER_HELP: &str = "\
FILES:
    A wallet is one encrypted file, <DIR>/<NAME>.sesame, where DIR defaults to
      Linux    $XDG_DATA_HOME/sesame  (~/.local/share/sesame)
      macOS    ~/Library/Application Support/sesame
      Windows  %LOCALAPPDATA%\\sesame
    There is no daemon and nothing is cached between commands: every command
    asks for the password. To back up or move a wallet, copy the file.

PASSWORDS:
    By default the password is prompted for on the terminal. For scripts use
    --password-file or --password-stdin; either way one trailing newline is
    removed.

EXIT STATUS:
    0  success
    1  failure
    2  usage error
    3  wallet or item not found
    4  wrong password (or corrupted wallet)";

/// A rootless, daemonless secret store.
///
/// Secrets live in an encrypted file under your home directory. Items are
/// found by attributes (like `service=github user=ann`), as with the Secret
/// Service API and `secret-tool`.
#[derive(Parser, Debug)]
#[command(name = "sesame", version, max_term_width = 100, after_help = AFTER_HELP)]
pub struct Cli {
    /// Directory that holds wallet files [default: per-user data directory]
    #[arg(long, global = true, env = "SESAME_DIR", value_name = "DIR")]
    pub dir: Option<PathBuf>,

    /// Which wallet to use
    #[arg(
        short,
        long,
        global = true,
        env = "SESAME_WALLET",
        value_name = "NAME",
        default_value = "default"
    )]
    pub wallet: String,

    /// Read the wallet password from FILE instead of prompting
    #[arg(
        long,
        global = true,
        env = "SESAME_PASSWORD_FILE",
        value_name = "FILE",
        hide_env_values = true
    )]
    pub password_file: Option<PathBuf>,

    /// Read the wallet password from standard input instead of prompting
    #[arg(long, global = true)]
    pub password_stdin: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new wallet
    Init(InitArgs),

    /// Store a secret, read from standard input or prompted for
    ///
    /// If an item with exactly the same attributes already exists it is
    /// updated in place, so storing is idempotent.
    ///
    /// When piped, the secret is taken from stdin byte for byte (including any
    /// trailing newline: use `printf` or `echo -n`, or --strip-newline).
    /// Secrets are never accepted on the command line, where other users could
    /// see them in the process list.
    #[command(visible_alias = "store")]
    Set(SetArgs),

    /// Print a secret to standard output
    ///
    /// The secret is written without a trailing newline, unless stdout is a
    /// terminal.
    #[command(visible_alias = "lookup")]
    Get(GetArgs),

    /// List items and their attributes (secrets are never shown)
    #[command(visible_aliases = ["ls", "search"])]
    List(ListArgs),

    /// Delete items
    #[command(visible_alias = "delete")]
    Rm(RmArgs),

    /// Change the wallet's password
    Passwd(PasswdArgs),

    /// List the wallets in the directory
    Wallets,

    /// Print the path of the selected wallet file
    Path,
}

impl Command {
    /// The subcommand's name as the user types it.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Init(_) => "init",
            Command::Set(_) => "set",
            Command::Get(_) => "get",
            Command::List(_) => "list",
            Command::Rm(_) => "rm",
            Command::Passwd(_) => "passwd",
            Command::Wallets => "wallets",
            Command::Path => "path",
        }
    }
}

/// Argon2id cost options. Lowering these makes the wallet easier to brute-force.
#[derive(Args, Debug)]
pub struct KdfArgs {
    /// Argon2id memory cost in MiB [default: 64]
    #[arg(long, value_name = "MIB")]
    pub kdf_memory_mib: Option<u32>,

    /// Argon2id number of passes [default: 3]
    #[arg(long, value_name = "N")]
    pub kdf_iterations: Option<u32>,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    #[command(flatten)]
    pub kdf: KdfArgs,
}

#[derive(Args, Debug)]
pub struct SetArgs {
    /// Attributes identifying the item, as ATTR=VALUE
    #[arg(value_name = "ATTR=VALUE", required = true, num_args = 1..)]
    pub attributes: Vec<String>,

    /// Human-readable label [default: the attribute values]
    #[arg(long)]
    pub label: Option<String>,

    /// MIME type of the secret
    #[arg(long, value_name = "TYPE")]
    pub content_type: Option<String>,

    /// Always add a new item, even if one with the same attributes exists
    #[arg(long)]
    pub no_replace: bool,

    /// Remove one trailing newline from piped input
    #[arg(long)]
    pub strip_newline: bool,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Attributes to match, as ATTR=VALUE
    #[arg(value_name = "ATTR=VALUE")]
    pub attributes: Vec<String>,

    /// Select by item id, or an unambiguous prefix of one (see `list`)
    #[arg(long, value_name = "ID", conflicts_with = "attributes")]
    pub id: Option<String>,

    /// If several items match, use the first instead of failing
    #[arg(long)]
    pub first: bool,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Only show items matching these attributes, as ATTR=VALUE
    #[arg(value_name = "ATTR=VALUE")]
    pub attributes: Vec<String>,

    /// Output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct RmArgs {
    /// Attributes to match, as ATTR=VALUE
    #[arg(value_name = "ATTR=VALUE")]
    pub attributes: Vec<String>,

    /// Select by item id, or an unambiguous prefix of one (see `list`)
    #[arg(long, value_name = "ID", conflicts_with = "attributes")]
    pub id: Option<String>,

    /// Delete every match rather than failing when there are several
    #[arg(long)]
    pub all: bool,
}

#[derive(Args, Debug)]
pub struct PasswdArgs {
    /// Read the new password from FILE instead of prompting
    #[arg(long, value_name = "FILE")]
    pub new_password_file: Option<PathBuf>,

    /// Argon2id cost options [default: keep the wallet's current cost]
    #[command(flatten)]
    pub kdf: KdfArgs,
}
