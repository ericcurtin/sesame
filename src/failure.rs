//! CLI errors and their exit codes.

use std::fmt;

/// Exit codes, documented in `--help`.
pub const EXIT_FAILURE: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_NOT_FOUND: u8 = 3;
pub const EXIT_AUTH: u8 = 4;

#[derive(Debug)]
pub enum CliError {
    /// The command line was wrong (exit 2, reported in clap's style).
    Usage(String),
    /// A wallet or item doesn't exist (exit 3).
    NotFound(String),
    /// Anything else that went wrong (exit 1).
    Failure(String),
    /// An error from the library, classified by [`CliError::exit_code`].
    Lib(sesame::Error),
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::Usage(_) => EXIT_USAGE,
            CliError::NotFound(_) => EXIT_NOT_FOUND,
            CliError::Failure(_) => EXIT_FAILURE,
            CliError::Lib(e) => match e {
                sesame::Error::WalletNotFound(_) | sesame::Error::ItemNotFound => EXIT_NOT_FOUND,
                sesame::Error::Authentication => EXIT_AUTH,
                _ => EXIT_FAILURE,
            },
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Usage(m) | CliError::NotFound(m) | CliError::Failure(m) => f.write_str(m),
            CliError::Lib(e) => e.fmt(f),
        }
    }
}

impl From<sesame::Error> for CliError {
    fn from(e: sesame::Error) -> Self {
        CliError::Lib(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes() {
        assert_eq!(CliError::Usage("x".into()).exit_code(), 2);
        assert_eq!(CliError::NotFound("x".into()).exit_code(), 3);
        assert_eq!(CliError::Failure("x".into()).exit_code(), 1);
        assert_eq!(CliError::Lib(sesame::Error::Authentication).exit_code(), 4);
        assert_eq!(CliError::Lib(sesame::Error::ItemNotFound).exit_code(), 3);
        assert_eq!(
            CliError::Lib(sesame::Error::WalletNotFound("p".into())).exit_code(),
            3
        );
        assert_eq!(CliError::Lib(sesame::Error::AmbiguousId).exit_code(), 1);
        assert_eq!(CliError::Lib(sesame::Error::WalletRekeyed).exit_code(), 1);
    }
}
