//! GitHub releases mirror source.

use anyhow::{Context, Result, bail};
use clap::Args;
use log::info;
use reqwest::header::USER_AGENT;
use serde::Deserialize;

use crate::alist::{self, url_unescape};
use crate::cli::{CHROME_UA, CommonArgs};

#[derive(Args, Debug)]
pub struct GithubArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// GitHub repository (e.g. owner/repo)
    #[arg(long)]
    pub repo: String,

    /// Optional regex pattern to filter assets by filename
    #[arg(long)]
    pub asset_filter: Option<String>,
}

/// GitHub release from the releases API.
#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
}

/// GitHub release asset.
#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

pub fn handle(args: GithubArgs) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async_handle(args))
}

async fn async_handle(args: GithubArgs) -> Result<()> {
    let (origin, root_path) = alist::parse_target(&args.common.target)?;
    let token = &args.common.token;

    if token.trim().is_empty() {
        bail!("alist token is empty");
    }

    let client = reqwest::Client::builder()
        .user_agent(CHROME_UA)
        .build()
        .context("building reqwest client")?;

    // Fetch latest release from GitHub API
    let api_url = format!("https://api.github.com/repos/{}/releases/latest", args.repo);
    info!("Fetching latest release from: {}", api_url);

    let resp = client
        .get(&api_url)
        .header(USER_AGENT, CHROME_UA)
        .send()
        .await
        .with_context(|| format!("fetching latest release from {}", api_url))?;

    if !resp.status().is_success() {
        bail!("failed to fetch latest release: status {}", resp.status());
    }

    let release: GitHubRelease = resp
        .json()
        .await
        .context("parsing GitHub release response")?;

    info!(
        "Found release {} with {} assets",
        release.tag_name,
        release.assets.len()
    );

    // Extract version from tag using regex
    let version = extract_version(&release.tag_name, &args.common.regex).unwrap_or_else(|| {
        info!(
            "Failed to extract version from tag using regex, using tag as-is: {}",
            release.tag_name
        );
        release.tag_name.clone()
    });

    // Filter assets if pattern provided
    let assets: Vec<&GitHubAsset> = if let Some(ref filter_pattern) = args.asset_filter {
        let re = regex::Regex::new(filter_pattern)
            .with_context(|| format!("invalid asset filter regex: {}", filter_pattern))?;
        release
            .assets
            .iter()
            .filter(|a| re.is_match(&a.name))
            .collect()
    } else {
        release.assets.iter().collect()
    };

    if assets.is_empty() {
        bail!("no assets found in release (after filtering)");
    }

    info!(
        "Mirroring {} assets for {} {}",
        assets.len(),
        args.common.name,
        version
    );

    // Mirror each asset
    for asset in assets {
        let dest_dir =
            alist::normalize_join(&root_path, &format!("{}/{}/", args.common.name, version));
        let dest_file_path = format!("{}{}", dest_dir, asset.name);
        let unescaped_dest_file_path = url_unescape(&dest_file_path);

        info!("Destination: {}", unescaped_dest_file_path);

        // Check if file already exists
        if alist::file_exists(&client, &origin, token, &unescaped_dest_file_path).await? {
            info!("File already exists, skipping: {}", asset.name);
            continue;
        }

        // Create offline download task
        alist::create_offline_download_task(
            &client,
            &origin,
            token,
            &asset.browser_download_url,
            &dest_dir,
            &args.common.tool,
        )
        .await?;

        info!("Offline download task created for: {}", asset.name);
    }

    info!("All offline download tasks submitted successfully");
    Ok(())
}

/// Extract version from string using regex pattern (first capture group).
fn extract_version(input: &str, pattern: &str) -> Option<String> {
    let re = regex::Regex::new(pattern).ok()?;
    re.captures(input)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_version() {
        assert_eq!(
            extract_version("v1.2.3", r"v([0-9.]+)"),
            Some("1.2.3".to_string())
        );
        assert_eq!(extract_version("1.2.3", r"v([0-9.]+)"), None);
    }
}
