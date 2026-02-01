//! Scoop manifest mirror source.

use anyhow::{Context, Result, bail};
use clap::Args;
use log::info;
use reqwest::header::USER_AGENT;
use serde::Deserialize;

use crate::alist;
use crate::cli::{CHROME_UA, CommonArgs};
use crate::utils::{http, mirror, version};

#[derive(Args, Debug)]
pub struct ScoopArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Scoop manifest URL (e.g. https://raw.githubusercontent.com/.../app.json)
    #[arg(long)]
    pub manifest_url: String,

    /// Optional architecture filter (e.g. x64, x86, arm64). If not provided, mirrors x64
    #[arg(long)]
    pub arch: Option<String>,

    /// Optional filename to use for the destination file (overrides filename from URL)
    #[arg(long)]
    pub filename: Option<String>,
}

#[derive(Debug, Clone)]
struct PackageUrl {
    url: String,
    version: String,
    arch: String,
}

#[derive(Deserialize)]
struct ScoopManifest {
    version: String,
    architecture: Option<ScoopArchitectures>,
    url: Option<ScoopTopLevelUrl>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ScoopTopLevelUrl {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Deserialize)]
struct ScoopArchitectures {
    #[serde(rename = "64bit")]
    x64: Option<ScoopArchData>,
    #[serde(rename = "32bit")]
    x86: Option<ScoopArchData>,
    arm64: Option<ScoopArchData>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ScoopArchData {
    /// Simple string URL
    Single(String),
    /// Array of URL strings
    Multiple(Vec<String>),
    /// Object with url field (and possibly hash, etc.)
    Object(ScoopArchObject),
}

#[derive(Deserialize)]
struct ScoopArchObject {
    url: Option<ScoopArchUrl>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ScoopArchUrl {
    Single(String),
    Multiple(Vec<String>),
}

pub fn handle(args: ScoopArgs) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async_handle(args))
}

async fn async_handle(args: ScoopArgs) -> Result<()> {
    let (origin, root_path) = alist::parse_target(&args.common.target)?;
    let token = &args.common.token;

    if token.trim().is_empty() {
        bail!("alist token is empty");
    }

    info!("Retrieved token for alist");

    let client = http::create_client()?;

    // Fetch and parse manifest to get download URLs
    info!("Fetching manifest from: {}", args.manifest_url);
    let mut package_urls = fetch_and_parse_manifest(&client, &args.manifest_url).await?;

    if package_urls.is_empty() {
        bail!("no package URLs found in manifest");
    }

    // Filter by architecture if specified
    if let Some(ref arch_filter) = args.arch {
        let original_count = package_urls.len();
        package_urls.retain(|pkg| pkg.arch == *arch_filter);
        info!(
            "Filtered to {} package(s) matching architecture: {} (from {} total)",
            package_urls.len(),
            arch_filter,
            original_count
        );

        if package_urls.is_empty() {
            bail!(
                "no package URLs found matching architecture: {}",
                arch_filter
            );
        }
    }

    info!("Found {} package URLs to mirror", package_urls.len());

    // Mirror each package URL
    for pkg in package_urls {
        // Extract version from URL using regex
        let version_for_path =
            version::extract_version(&pkg.url, &args.common.regex).unwrap_or_else(|| {
                info!(
                    "Failed to extract version from URL using regex, falling back to manifest version: {}",
                    pkg.version
                );
                pkg.version.clone()
            });

        info!("Mirroring {} {}", args.common.name, version_for_path);

        let filename = version::determine_filename(
            args.filename.as_deref(),
            &pkg.url,
            &args.common.name,
            &version_for_path,
        );

        let log_prefix = format!("{}-{}", args.common.name, pkg.arch);
        mirror::mirror_file(
            &client,
            &origin,
            token,
            &pkg.url,
            &root_path,
            &args.common.name,
            &version_for_path,
            &filename,
            &args.common.tool,
            &log_prefix,
        )
        .await?;
    }

    info!("All offline download tasks submitted successfully");
    Ok(())
}

async fn fetch_and_parse_manifest(
    client: &reqwest::Client,
    manifest_url: &str,
) -> Result<Vec<PackageUrl>> {
    let resp = client
        .get(manifest_url)
        .header(USER_AGENT, CHROME_UA)
        .send()
        .await
        .with_context(|| format!("fetching manifest from {}", manifest_url))?;

    if !resp.status().is_success() {
        bail!("failed to fetch manifest: status {}", resp.status());
    }

    let content = resp
        .text()
        .await
        .context("reading manifest response body")?;

    parse_scoop_manifest(&content)
}

fn parse_scoop_manifest(content: &str) -> Result<Vec<PackageUrl>> {
    let manifest: ScoopManifest =
        serde_json::from_str(content).context("parsing scoop manifest JSON")?;

    let mut urls = Vec::new();
    let version = manifest.version.clone();

    // Helper function to extract URLs from ScoopArchData
    fn extract_urls_from_arch_data(arch_data: &ScoopArchData) -> Option<Vec<String>> {
        match arch_data {
            ScoopArchData::Single(url) => Some(vec![url.clone()]),
            ScoopArchData::Multiple(url_list) => Some(url_list.clone()),
            ScoopArchData::Object(obj) => match &obj.url {
                Some(ScoopArchUrl::Single(url)) => Some(vec![url.clone()]),
                Some(ScoopArchUrl::Multiple(url_list)) => Some(url_list.clone()),
                _ => None,
            },
        }
    }

    // Extract all architectures
    if let Some(ref arch) = manifest.architecture {
        // 64bit
        if let Some(ref x64_data) = arch.x64
            && let Some(urls_from_arch) = extract_urls_from_arch_data(x64_data)
        {
            for url in urls_from_arch {
                urls.push(PackageUrl {
                    url,
                    version: version.clone(),
                    arch: "x64".to_string(),
                });
            }
        }

        // 32bit
        if let Some(ref x86_data) = arch.x86
            && let Some(urls_from_arch) = extract_urls_from_arch_data(x86_data)
        {
            for url in urls_from_arch {
                urls.push(PackageUrl {
                    url,
                    version: version.clone(),
                    arch: "x86".to_string(),
                });
            }
        }

        // arm64
        if let Some(ref arm64_data) = arch.arm64
            && let Some(urls_from_arch) = extract_urls_from_arch_data(arm64_data)
        {
            for url in urls_from_arch {
                urls.push(PackageUrl {
                    url,
                    version: version.clone(),
                    arch: "arm64".to_string(),
                });
            }
        }
    }

    // If no architecture-specific URLs found, check for top-level url field
    if urls.is_empty()
        && let Some(top_level_url) = manifest.url
    {
        let url_list = match top_level_url {
            ScoopTopLevelUrl::Single(url) => vec![url],
            ScoopTopLevelUrl::Multiple(url_list) => url_list,
        };

        for url in url_list {
            urls.push(PackageUrl {
                url,
                version: version.clone(),
                arch: "x64".to_string(),
            });
        }
    }

    Ok(urls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::version;

    #[test]
    fn test_parse_scoop_manifest_single_url() {
        let content = r#"{
            "version": "1.2.3",
            "architecture": {
                "64bit": "https://example.com/package.zip"
            }
        }"#;
        let result = parse_scoop_manifest(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].version, "1.2.3");
        assert_eq!(result[0].arch, "x64");
    }

    #[test]
    fn test_parse_scoop_manifest_multiple_urls() {
        let content = r#"{
            "version": "2.0.0",
            "architecture": {
                "64bit": [
                    "https://example.com/package1.zip",
                    "https://example.com/package2.zip"
                ]
            }
        }"#;
        let result = parse_scoop_manifest(content).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].version, "2.0.0");
        assert_eq!(result[1].version, "2.0.0");
    }

    #[test]
    fn test_parse_scoop_firefox_manifest() {
        let content = r#"{
            "version": "145.0.1",
            "description": "Popular open source web browser.",
            "homepage": "https://www.firefox.com/",
            "license": "MPL-2.0",
            "architecture": {
                "64bit": {
                    "url": "https://archive.mozilla.org/pub/firefox/releases/145.0.1/win64/en-US/Firefox%20Setup%20145.0.1.exe#/dl.7z",
                    "hash": "sha512:abc123"
                },
                "32bit": {
                    "url": "https://archive.mozilla.org/pub/firefox/releases/145.0.1/win32/en-US/Firefox%20Setup%20145.0.1.exe#/dl.7z",
                    "hash": "sha512:def456"
                },
                "arm64": {
                    "url": "https://archive.mozilla.org/pub/firefox/releases/145.0.1/win64-aarch64/en-US/Firefox%20Setup%20145.0.1.exe#/dl.7z",
                    "hash": "sha512:ghi789"
                }
            }
        }"#;

        let result = parse_scoop_manifest(content).unwrap();

        // Should parse all architectures
        assert_eq!(result.len(), 3);

        let x64_pkg = result.iter().find(|p| p.arch == "x64").unwrap();
        assert_eq!(x64_pkg.version, "145.0.1");
        assert!(x64_pkg.url.contains("win64/en-US"));

        let x86_pkg = result.iter().find(|p| p.arch == "x86").unwrap();
        assert!(x86_pkg.url.contains("win32/en-US"));

        let arm64_pkg = result.iter().find(|p| p.arch == "arm64").unwrap();
        assert!(arm64_pkg.url.contains("win64-aarch64"));
    }

    #[test]
    fn test_parse_scoop_top_level_url() {
        let content = r#"{
            "version": "6.5.5",
            "url": "https://downloads.sourceforge.net/project/winscp/WinSCP/6.5.5/WinSCP-6.5.5-Portable.zip"
        }"#;

        let result = parse_scoop_manifest(content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].version, "6.5.5");
        assert_eq!(result[0].arch, "x64");
        assert!(result[0].url.contains("WinSCP-6.5.5-Portable.zip"));
    }

    #[test]
    fn test_filename_from_url() {
        assert_eq!(
            version::filename_from_url("https://example.com/path/file.zip"),
            Some("file.zip".to_string())
        );
        assert_eq!(
            version::filename_from_url("https://example.com/path/file.zip?param=value"),
            Some("file.zip".to_string())
        );
        assert_eq!(version::filename_from_url("https://example.com/"), None);
        assert_eq!(
            version::filename_from_url("https://example.com/installer.exe#/install.exe"),
            Some("installer.exe".to_string())
        );
    }

    #[test]
    fn test_extract_version() {
        assert_eq!(
            version::extract_version("v1.2.3", r"v([0-9.]+)"),
            Some("1.2.3".to_string())
        );
        assert_eq!(version::extract_version("1.2.3", r"v([0-9.]+)"), None);
    }
}
