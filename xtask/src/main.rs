//! xtask runner for cloud-identity-wallet.
//!
//! Provides profile-based commands that configure the correct Cargo features
//! for each deployment environment (development, staging, production).
//!
//! # Profiles
//!
//! - `development`: Memory backends + local KMS (no external services needed)
//! - `staging`: PostgreSQL + Redis + local KMS (for pre-production testing)
//! - `production`: PostgreSQL + Redis + AWS KMS (for production deployment)
//!
//! Usage:
//!   cargo xtask run development    # Build and run with development profile
//!   cargo xtask run staging        # Build and run with staging profile
//!   cargo xtask run production     # Build and run with production profile
//!   cargo xtask build <profile>    # Build with a given profile
//!   cargo xtask check <profile>    # Check with a given profile
//!   cargo xtask test <profile>     # Run tests with a given profile
//!   cargo xtask features <profile> # Print the Cargo features for a profile
//!   cargo xtask list               # List available profiles
//!   cargo xtask dev                # Alias for `run development`

#![allow(rustdoc::invalid_html_tags)]

use clap::{Parser, Subcommand};
use std::process::Command;

/// Deployment profiles that map to specific Cargo feature combinations.
#[derive(Clone, Debug, clap::ValueEnum)]
enum Profile {
    /// Memory backends + local KMS (default, no external services)
    Development,
    /// PostgreSQL + Redis + local KMS (pre-production)
    Staging,
    /// PostgreSQL + Redis + AWS KMS (production)
    Production,
}

impl Profile {
    /// Returns the Cargo features for this profile.
    fn features(&self) -> &[&str] {
        match self {
            Self::Development => &["memory", "local-kms"],
            Self::Staging => &["postgres", "redis", "local-kms"],
            Self::Production => &["postgres", "redis", "aws-kms"],
        }
    }
}

/// Task runner for cloud-identity-wallet deployment profiles.
#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Task runner for cloud-identity-wallet",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the project with a specific profile
    Build {
        /// Deployment profile
        profile: Profile,
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Check the project with a specific profile
    Check {
        /// Deployment profile
        profile: Profile,
    },
    /// Run the project with a specific profile
    Run {
        /// Deployment profile
        profile: Profile,
        /// Run in release mode
        #[arg(long)]
        release: bool,
    },
    /// Run tests with a specific profile
    Test {
        /// Deployment profile
        profile: Profile,
    },
    /// Print the Cargo features for a given profile
    Features {
        /// Deployment profile
        profile: Profile,
    },
    /// List all available profiles and their features
    List,
    /// Alias for `run development`
    Dev {
        /// Run in release mode
        #[arg(long)]
        release: bool,
    },
}

fn cargo() -> Command {
    Command::new("cargo")
}

fn run_command(cmd: &mut Command) -> i32 {
    let status = cmd.status().expect("failed to execute command");
    status.code().unwrap_or(1)
}

fn features_arg(profile: &Profile) -> Vec<String> {
    let mut args = vec!["--no-default-features".to_string()];
    let mut features_str = String::new();
    for (i, f) in profile.features().iter().enumerate() {
        if i > 0 {
            features_str.push(',');
        }
        features_str.push_str(f);
    }
    args.push("--features".to_string());
    args.push(features_str);
    args
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Build { profile, release } => {
            let mut cmd = cargo();
            cmd.args(["build"]);
            if release {
                cmd.arg("--release");
            }
            cmd.args(features_arg(&profile));
            std::process::exit(run_command(&mut cmd));
        }
        Commands::Check { profile } => {
            let mut cmd = cargo();
            cmd.args(["check"]);
            cmd.args(features_arg(&profile));
            std::process::exit(run_command(&mut cmd));
        }
        Commands::Run { profile, release } => {
            let mut cmd = cargo();
            cmd.args(["run"]);
            if release {
                cmd.arg("--release");
            }
            cmd.args(features_arg(&profile));
            std::process::exit(run_command(&mut cmd));
        }
        Commands::Test { profile } => {
            let mut cmd = cargo();
            cmd.args(["test"]);
            cmd.args(features_arg(&profile));
            std::process::exit(run_command(&mut cmd));
        }
        Commands::Features { profile } => {
            println!("{}", profile.features().join(","));
        }
        Commands::List => {
            println!("Available profiles:\n");
            for p in [Profile::Development, Profile::Staging, Profile::Production] {
                println!(
                    "  {:12} → {}",
                    format!("{:?}", p).to_lowercase(),
                    p.features().join(", ")
                );
            }
            println!(
                "\nUsage:\n  \
                 cargo xtask run development\n  \
                 cargo xtask build staging --release\n  \
                 cargo xtask test production\n  \
                 cargo xtask dev\n  \
                 cargo xtask features staging"
            );
        }
        Commands::Dev { release } => {
            let mut cmd = cargo();
            cmd.args(["run"]);
            if release {
                cmd.arg("--release");
            }
            cmd.args(features_arg(&Profile::Development));
            std::process::exit(run_command(&mut cmd));
        }
    }
}
