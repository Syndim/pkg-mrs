use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use env_logger::Env;
use log::info;

use crate::config::{Config, MirrorConfig, MirrorSource};
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

/// Arguments for the sync command
#[derive(clap::Args, Debug)]
pub struct SyncArgs {
    /// Path to config file (default: ~/.config/pkg-mrs/config.toml)
    #[arg(long, short)]
    pub config: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Mirror packages from GitHub releases
    Github(github::GithubArgs),
    /// Mirror packages from Homebrew/Scoop manifests
    Homebrew(homebrew::HomebrewArgs),
    /// Run all mirrors defined in config file
    Sync(SyncArgs),
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
        Commands::Sync(args) => run_from_config(args),
    }
}

/// Run all mirrors defined in the config file.
fn run_from_config(args: SyncArgs) -> Result<()> {
    let config = if let Some(path) = args.config {
        Config::load_from(&path)?
    } else {
        Config::load()?
    };

    if config.mirrors.is_empty() {
        bail!("no mirrors defined in config file");
    }

    let default_target = config.get_target()?;
    let default_token = config.get_token()?;
    let default_tool = &config.settings.tool;

    info!("Running {} mirror(s) from config", config.mirrors.len());

    let mut errors = Vec::new();

    for mirror in &config.mirrors {
        info!("=== Mirroring: {} ===", mirror.name);

        let result = run_mirror(mirror, &default_target, &default_token, default_tool);

        if let Err(e) = result {
            log::error!("Failed to mirror {}: {}", mirror.name, e);
            errors.push((mirror.name.clone(), e));
        }
    }

    if errors.is_empty() {
        info!("All mirrors completed successfully");
        Ok(())
    } else {
        bail!(
            "{} mirror(s) failed: {}",
            errors.len(),
            errors
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

/// Run a single mirror from config.
fn run_mirror(
    mirror: &MirrorConfig,
    default_target: &str,
    default_token: &str,
    default_tool: &str,
) -> Result<()> {
    let target = mirror.target.as_deref().unwrap_or(default_target);
    let tool = mirror.tool.as_deref().unwrap_or(default_tool);

    match &mirror.source {
        MirrorSource::Github(gh) => {
            let args = github::GithubArgs {
                common: CommonArgs {
                    name: mirror.name.clone(),
                    target: target.to_string(),
                    token: default_token.to_string(),
                    tool: tool.to_string(),
                    regex: mirror.regex.clone(),
                },
                repo: gh.repo.clone(),
                asset_filter: gh.asset_filter.clone(),
            };

            github::handle(args)
        }
        MirrorSource::Homebrew(hb) => {
            let args = homebrew::HomebrewArgs {
                common: CommonArgs {
                    name: mirror.name.clone(),
                    target: target.to_string(),
                    token: default_token.to_string(),
                    tool: tool.to_string(),
                    regex: mirror.regex.clone(),
                },
                manifest_url: hb.manifest_url.clone(),
                arch: hb.arch.clone(),
                filename: hb.filename.clone(),
                language: hb.language.clone(),
            };

            homebrew::handle(args)
        }
    }
}
