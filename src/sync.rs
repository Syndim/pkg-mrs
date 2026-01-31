//! Sync command - run all mirrors from config file.

use std::path::PathBuf;

use anyhow::{Result, bail};
use log::info;

use crate::cli::CommonArgs;
use crate::config::{Config, MirrorConfig, MirrorSource};
use crate::sources::{github, homebrew, scoop};

/// Arguments for the sync command
#[derive(clap::Args, Debug)]
pub struct SyncArgs {
    /// Path to config file (default: ~/.config/pkg-mrs/config.toml)
    #[arg(long, short)]
    pub config: Option<PathBuf>,
}

/// Run all mirrors defined in the config file.
pub fn handle(args: SyncArgs) -> Result<()> {
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
        MirrorSource::Scoop(sc) => {
            let args = scoop::ScoopArgs {
                common: CommonArgs {
                    name: mirror.name.clone(),
                    target: target.to_string(),
                    token: default_token.to_string(),
                    tool: tool.to_string(),
                    regex: mirror.regex.clone(),
                },
                manifest_url: sc.manifest_url.clone(),
                arch: sc.arch.clone(),
                filename: sc.filename.clone(),
            };

            scoop::handle(args)
        }
    }
}
