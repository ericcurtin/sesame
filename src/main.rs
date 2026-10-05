//! The `sesame` command-line tool. See the library crate for the design.

#![deny(unsafe_code)]

mod args;
mod commands;
mod failure;
mod harden;
mod prompt;
mod timefmt;

use std::process::ExitCode;

use clap::{CommandFactory, Parser, error::ErrorKind};

use crate::{args::Cli, failure::CliError};

fn main() -> ExitCode {
    harden::apply();

    let cli = Cli::parse();
    let subcommand = cli.command.name();
    match commands::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        // Report usage mistakes the way clap reports its own, so they look and
        // exit (status 2) the same, with the failing subcommand's usage line.
        Err(CliError::Usage(message)) => usage_error(subcommand, message),
        Err(e) => {
            eprintln!("sesame: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

fn usage_error(subcommand: &str, message: String) -> ! {
    let mut root = Cli::command();
    // Building propagates the binary name, so the usage line reads
    // `sesame get ...` rather than just `get ...`.
    root.build();
    match root.find_subcommand_mut(subcommand) {
        Some(sub) => sub.error(ErrorKind::InvalidValue, message).exit(),
        None => root.error(ErrorKind::InvalidValue, message).exit(),
    }
}
