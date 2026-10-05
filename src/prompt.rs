//! Getting passwords and secrets from the user, files and pipes.

use std::{
    fs,
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
};

use sesame::Secret;
use zeroize::Zeroizing;

use crate::failure::CliError;

/// Largest secret accepted on stdin.
const MAX_SECRET_LEN: u64 = 16 * 1024 * 1024;

/// Where the wallet password comes from.
#[derive(Debug)]
pub enum PasswordSource {
    /// Ask on the terminal.
    Prompt,
    /// Read all of standard input.
    Stdin,
    /// Read a file.
    File(PathBuf),
}

impl PasswordSource {
    pub fn from_args(file: Option<PathBuf>, stdin: bool) -> Result<Self, CliError> {
        match (file, stdin) {
            (Some(_), true) => Err(CliError::Usage(
                "--password-file and --password-stdin cannot be used together".into(),
            )),
            (Some(path), false) => Ok(PasswordSource::File(path)),
            (None, true) => Ok(PasswordSource::Stdin),
            (None, false) => Ok(PasswordSource::Prompt),
        }
    }

    pub fn uses_stdin(&self) -> bool {
        matches!(self, PasswordSource::Stdin)
    }

    /// The password of an existing wallet.
    pub fn existing(&self, wallet: &str) -> Result<Zeroizing<String>, CliError> {
        match self {
            PasswordSource::Prompt => prompt(&format!("Password for wallet '{wallet}': ")),
            PasswordSource::Stdin => from_stdin(),
            PasswordSource::File(path) => from_file(path),
        }
    }

    /// A new password, asked for twice when typed.
    pub fn new_password(&self, wallet: &str) -> Result<Zeroizing<String>, CliError> {
        match self {
            PasswordSource::Prompt => new_password_prompt(wallet),
            PasswordSource::Stdin => from_stdin(),
            PasswordSource::File(path) => from_file(path),
        }
    }
}

/// Prompt for a new password and its confirmation.
pub fn new_password_prompt(wallet: &str) -> Result<Zeroizing<String>, CliError> {
    let first = prompt(&format!("New password for wallet '{wallet}': "))?;
    let second = prompt("Confirm password: ")?;
    if *first != *second {
        return Err(CliError::Failure("passwords do not match".into()));
    }
    Ok(first)
}

/// Read a password from a file.
pub fn from_file(path: &Path) -> Result<Zeroizing<String>, CliError> {
    let bytes = fs::read(path).map_err(|e| {
        CliError::Failure(format!("cannot read password file {}: {e}", path.display()))
    })?;
    from_bytes(bytes, "password file")
}

fn from_stdin() -> Result<Zeroizing<String>, CliError> {
    let mut buf = Zeroizing::new(Vec::with_capacity(1024));
    io::stdin()
        .lock()
        .take(1024 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| CliError::Failure(format!("cannot read password from stdin: {e}")))?;
    from_bytes(std::mem::take(&mut *buf), "password on stdin")
}

/// Turn raw bytes into a password: drop one trailing newline, require UTF-8.
fn from_bytes(bytes: Vec<u8>, what: &str) -> Result<Zeroizing<String>, CliError> {
    let mut bytes = Zeroizing::new(bytes);
    strip_one_newline(&mut bytes);
    match std::str::from_utf8(&bytes) {
        Ok(s) => Ok(Zeroizing::new(s.to_owned())),
        Err(_) => Err(CliError::Failure(format!("{what} is not valid UTF-8"))),
    }
}

/// Remove a single trailing `\n` or `\r\n`.
pub fn strip_one_newline(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
}

/// Prompt on the terminal without echo.
///
/// rpassword talks to the controlling terminal directly (`/dev/tty`, or the
/// console on Windows), not stdin/stdout, so prompting still works when a
/// secret is being piped in and output is being captured.
pub fn prompt(message: &str) -> Result<Zeroizing<String>, CliError> {
    rpassword::prompt_password(message)
        .map(Zeroizing::new)
        .map_err(|e| match e.kind() {
            io::ErrorKind::Interrupted => CliError::Failure("interrupted".into()),
            _ => CliError::Failure(format!(
                "cannot prompt for input ({e}); no terminal available? \
                 use --password-file or --password-stdin"
            )),
        })
}

/// Read the secret for `set`: prompted for if stdin is a terminal, otherwise
/// read from the pipe exactly as given.
pub fn read_secret(strip_newline: bool) -> Result<Secret, CliError> {
    if io::stdin().is_terminal() {
        let first = prompt("Secret: ")?;
        let second = prompt("Confirm secret: ")?;
        if *first != *second {
            return Err(CliError::Failure("secrets do not match".into()));
        }
        return Ok(Secret::from_slice(first.as_bytes()));
    }

    // Sized so a typical secret never forces a reallocation, which would leave
    // an unwiped copy behind.
    let mut buf = Zeroizing::new(Vec::with_capacity(64 * 1024));
    io::stdin()
        .lock()
        .take(MAX_SECRET_LEN + 1)
        .read_to_end(&mut buf)
        .map_err(|e| CliError::Failure(format!("cannot read secret from stdin: {e}")))?;
    if buf.len() as u64 > MAX_SECRET_LEN {
        return Err(CliError::Failure(format!(
            "secret is larger than {} MiB",
            MAX_SECRET_LEN / (1024 * 1024)
        )));
    }
    if strip_newline {
        strip_one_newline(&mut buf);
    }
    Ok(Secret::new(std::mem::take(&mut *buf)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip(s: &[u8]) -> Vec<u8> {
        let mut v = s.to_vec();
        strip_one_newline(&mut v);
        v
    }

    #[test]
    fn strips_exactly_one_trailing_newline() {
        assert_eq!(strip(b"pw"), b"pw");
        assert_eq!(strip(b"pw\n"), b"pw");
        assert_eq!(strip(b"pw\r\n"), b"pw");
        assert_eq!(strip(b"pw\n\n"), b"pw\n");
        assert_eq!(strip(b"pw\r"), b"pw\r", "a lone CR is part of the password");
        assert_eq!(strip(b"\n"), b"");
        assert_eq!(strip(b""), b"");
        assert_eq!(strip(b" pw "), b" pw ", "spaces are significant");
    }

    #[test]
    fn password_bytes_must_be_utf8() {
        assert_eq!(
            &**from_bytes(b"caf\xc3\xa9\n".to_vec(), "x").unwrap(),
            "café"
        );
        assert!(from_bytes(vec![0xff, 0xfe], "x").is_err());
    }

    #[test]
    fn source_selection() {
        assert!(matches!(
            PasswordSource::from_args(None, false).unwrap(),
            PasswordSource::Prompt
        ));
        assert!(matches!(
            PasswordSource::from_args(None, true).unwrap(),
            PasswordSource::Stdin
        ));
        assert!(matches!(
            PasswordSource::from_args(Some("f".into()), false).unwrap(),
            PasswordSource::File(_)
        ));
        assert!(matches!(
            PasswordSource::from_args(Some("f".into()), true),
            Err(CliError::Usage(_))
        ));
    }
}
