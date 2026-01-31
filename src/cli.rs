use anyhow::Result;
use clap::{Parser, Subcommand};
use env_logger::Env;

use crate::sources::{github, homebrew};

pub const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36";

/// Common arguments for mirror commands
#[derive(clap::Args, Debug, Clone)]
pub struct CommonArgs {
    /// Package name (used in destination path hierarchy)
    #[arg(long)]
    pub name: String,

    /// Destination root URL including path prefix (e.g. https://example.com/packages)
    #[arg(long)]
    pub target: String,

    /// Alist API token for authentication
    #[arg(long, env = "ALIST_TOKEN")]
    pub token: String,

    /// Optional download tool hint (aria2/qbittorrent/transmission)
    #[arg(long, default_value = "aria2")]
    pub tool: String,

    /// Regex pattern to extract version (uses first capture group)
    #[arg(long)]
    pub regex: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Mirror packages from GitHub releases
    Github(github::GithubArgs),
    /// Mirror packages from Homebrew/Scoop manifests
    Homebrew(homebrew::HomebrewArgs),
}

#[derive(Parser, Debug)]
#[command(name = "pkg-mrs", version, about = "Package Mirror CLI - Mirror packages to alist storage", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

pub fn run() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Github(args) => github::handle(args),
        Commands::Homebrew(args) => homebrew::handle(args),
    }
}
