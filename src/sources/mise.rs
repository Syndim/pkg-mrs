//! Mise registry mirror source.
//!
//! Mirrors packages defined in mise registry TOML files.
//! Supports HTTP backends with URL templates that can include:
//! - `{{ version }}` - package version
//! - `{{ os() }}` - operating system (with optional remapping)
//! - `{{ arch() }}` - CPU architecture (with optional remapping)
//!
//! Example registry: https://github.com/jdx/mise/blob/main/registry/flutter.toml

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use clap::Args;
use log::info;
use regex::Regex;
use serde::Deserialize;
use tera::Tera;

use crate::alist;
use crate::utils::{http, mirror, version};

/// Common platforms supported by mise (from Platform::common_platforms())
pub const COMMON_PLATFORMS: &[(&str, &str)] = &[
    ("linux", "x64"),
    ("linux", "arm64"),
    ("macos", "x64"),
    ("macos", "arm64"),
    ("windows", "x64"),
];

#[derive(Args, Debug)]
pub struct MiseArgs {
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

    /// Mise registry TOML URL (e.g. https://raw.githubusercontent.com/jdx/mise/main/registry/flutter.toml)
    #[arg(long)]
    pub manifest_url: String,
}

/// Mise registry TOML structure
#[derive(Debug, Deserialize)]
pub struct MiseRegistry {
    #[serde(default)]
    pub backends: Vec<Backend>,
}

#[derive(Debug, Deserialize)]
pub struct Backend {
    /// Full backend identifier (e.g. "http:flutter")
    pub full: String,
    #[serde(default)]
    pub options: BackendOptions,
}

#[derive(Debug, Deserialize, Default)]
pub struct BackendOptions {
    /// URL template for downloading
    pub url: Option<String>,
    /// URL to fetch version list from
    pub version_list_url: Option<String>,
    /// JQ-like path to extract versions from JSON response
    pub version_json_path: Option<String>,
    /// Regex pattern to extract versions from text response
    pub version_regex: Option<String>,
    /// Platform-specific URL overrides
    #[serde(default)]
    pub platforms: HashMap<String, PlatformOptions>,
}

#[derive(Debug, Deserialize, Default)]
pub struct PlatformOptions {
    pub url: Option<String>,
}

pub fn handle(args: MiseArgs) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async_handle(args))
}

async fn async_handle(args: MiseArgs) -> Result<()> {
    let (origin, root_path) = alist::parse_target(&args.target)?;
    let token = &args.token;

    if token.trim().is_empty() {
        bail!("alist token is empty");
    }

    let client = http::create_client()?;

    // Fetch mise registry TOML
    info!("Fetching mise registry from: {}", args.manifest_url);
    let resp = client
        .get(&args.manifest_url)
        .send()
        .await
        .with_context(|| format!("fetching mise registry from {}", args.manifest_url))?;

    if !resp.status().is_success() {
        bail!("failed to fetch mise registry: status {}", resp.status());
    }

    let content = resp
        .text()
        .await
        .context("reading mise registry response")?;

    let registry: MiseRegistry =
        toml::from_str(&content).context("parsing mise registry TOML")?;

    // Find HTTP backend
    let http_backend = registry
        .backends
        .iter()
        .find(|b| b.full.starts_with("http:"))
        .ok_or_else(|| anyhow::anyhow!("no HTTP backend found in mise registry"))?;

    let base_url = http_backend
        .options
        .url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("HTTP backend has no URL template"))?;

    let version_list_url = http_backend
        .options
        .version_list_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("HTTP backend has no version_list_url"))?;

    info!("Fetching version list from: {}", version_list_url);

    // Fetch and parse version
    let version = fetch_latest_version(
        &client,
        version_list_url,
        http_backend.options.version_json_path.as_deref(),
        http_backend.options.version_regex.as_deref(),
    )
    .await?;

    info!("Latest version: {}", version);

    // Mirror for each platform
    for (os, arch) in COMMON_PLATFORMS {
        let platform_key = format!("{}-{}", os, arch);

        // Check for platform-specific URL override
        let url_template = http_backend
            .options
            .platforms
            .get(&platform_key)
            .and_then(|p| p.url.as_ref())
            .unwrap_or(base_url);

        // Render URL template
        let url = match render_url_template(url_template, &version, os, arch) {
            Ok(u) => u,
            Err(e) => {
                info!("Skipping {} (template error: {})", platform_key, e);
                continue;
            }
        };

        // Check if URL is accessible using HEAD request (like mise does)
        if !check_url_exists(&client, &url).await {
            info!("[{}] URL not available, skipping: {}", platform_key, url);
            continue;
        }

        // Extract filename from URL
        let filename = version::filename_from_url(&url).unwrap_or_else(|| "download".to_string());

        mirror::mirror_file(
            &client,
            &origin,
            token,
            &url,
            &root_path,
            &args.name,
            &version,
            &filename,
            &args.tool,
            &platform_key,
        )
        .await?;
    }

    info!("All offline download tasks submitted successfully");
    Ok(())
}

/// Check if a URL exists using HTTP HEAD request (like mise does in aqua.rs and github.rs)
pub async fn check_url_exists(client: &reqwest::Client, url: &str) -> bool {
    match client.head(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                // Also check Content-Type - if it's text/html, we might have hit a login page
                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if content_type.contains("text/html") {
                    info!("URL returned HTML (likely error page), treating as unavailable");
                    return false;
                }
                true
            } else {
                info!("URL returned status {}", status);
                false
            }
        }
        Err(e) => {
            info!("HEAD request failed: {}", e);
            false
        }
    }
}

/// Fetch the latest version from a version list URL
pub async fn fetch_latest_version(
    client: &reqwest::Client,
    url: &str,
    json_path: Option<&str>,
    version_regex: Option<&str>,
) -> Result<String> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching version list from {}", url))?;

    if !resp.status().is_success() {
        bail!("failed to fetch version list: status {}", resp.status());
    }

    let content = resp.text().await.context("reading version list response")?;

    // Try to parse as JSON first
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
        let versions = if let Some(path) = json_path {
            jq::extract(&json, path)?
        } else {
            jq::extract_auto(&json)
        };

        if let Some(version) = versions.into_iter().next() {
            return Ok(version);
        }
    }

    // Fall back to regex extraction from text
    if let Some(pattern) = version_regex {
        let re = Regex::new(pattern).context("invalid version_regex pattern")?;
        if let Some(caps) = re.captures(&content) {
            if let Some(m) = caps.get(1) {
                return Ok(m.as_str().to_string());
            }
        }
    }

    // Try line-by-line version extraction (for simple text responses like claude's version_list_url)
    for line in content.lines() {
        let trimmed = line.trim().trim_start_matches('v');
        if !trimmed.is_empty() && trimmed.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return Ok(trimmed.to_string());
        }
    }

    bail!("could not extract version from version list")
}

/// Render a URL template with version, os, and arch
pub fn render_url_template(
    template: &str,
    version: &str,
    os: &str,
    arch: &str,
) -> Result<String> {
    let mut tera = Tera::default();

    // Register custom os() function
    let os_val = os.to_string();
    tera.register_function(
        "os",
        move |args: &HashMap<String, tera::Value>| -> tera::Result<tera::Value> {
            // Check for remapping (e.g., os(macos="darwin"))
            if let Some(val) = args.get(&os_val) {
                if let Some(s) = val.as_str() {
                    return Ok(tera::Value::String(s.to_string()));
                }
            }
            Ok(tera::Value::String(os_val.clone()))
        },
    );

    // Register custom arch() function
    let arch_val = arch.to_string();
    tera.register_function(
        "arch",
        move |args: &HashMap<String, tera::Value>| -> tera::Result<tera::Value> {
            // Check for remapping (e.g., arch(x64="amd64"))
            if let Some(val) = args.get(&arch_val) {
                if let Some(s) = val.as_str() {
                    return Ok(tera::Value::String(s.to_string()));
                }
            }
            Ok(tera::Value::String(arch_val.clone()))
        },
    );

    // Create context with version
    let mut context = tera::Context::new();
    context.insert("version", version);

    // Render template
    tera.render_str(template, &context)
        .with_context(|| format!("rendering URL template: {}", template))
}

/// Get URL template for a specific platform from registry options
pub fn get_platform_url<'a>(
    options: &'a BackendOptions,
    os: &str,
    arch: &str,
) -> Option<&'a str> {
    let platform_key = format!("{}-{}", os, arch);
    options
        .platforms
        .get(&platform_key)
        .and_then(|p| p.url.as_deref())
        .or(options.url.as_deref())
}

/// Simplified jq-like JSON path extraction (ported from mise)
pub mod jq {
    use anyhow::Result;

    /// Extract string values from JSON using a jq-like path expression
    pub fn extract(json: &serde_json::Value, path: &str) -> Result<Vec<String>> {
        let mut results = Vec::new();
        let path = path.trim();

        // Handle empty path or "." as root
        if path.is_empty() || path == "." {
            extract_values(json, &mut results);
            return Ok(results);
        }

        // Remove leading dot if present
        let path = path.strip_prefix('.').unwrap_or(path);

        // Parse the path and extract values
        extract_recursive(json, path, &mut results);

        Ok(results)
    }

    /// Extract values with auto-detection of common version patterns
    pub fn extract_auto(json: &serde_json::Value) -> Vec<String> {
        let mut results = Vec::new();

        match json {
            serde_json::Value::String(s) => {
                let v = normalize_version(s);
                if !v.is_empty() {
                    results.push(v);
                }
            }
            serde_json::Value::Array(arr) => {
                for val in arr {
                    if let Some(v) = val.as_str() {
                        let v = normalize_version(v);
                        if !v.is_empty() {
                            results.push(v);
                        }
                    } else if let Some(obj) = val.as_object() {
                        // Try common version field names
                        for field in ["version", "tag_name", "name", "tag", "v"] {
                            if let Some(v) = obj.get(field).and_then(|v| v.as_str()) {
                                let v = normalize_version(v);
                                if !v.is_empty() {
                                    results.push(v);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            serde_json::Value::Object(obj) => {
                // Check for common patterns like {"versions": [...]} or {"releases": [...]}
                for field in ["versions", "releases", "tags", "version", "release"] {
                    if let Some(val) = obj.get(field) {
                        // Handle HashiCorp-style {"versions": {"0.1.0": {...}, "0.2.0": {...}}}
                        // where versions are object keys
                        if let Some(inner_obj) = val.as_object() {
                            let mut version_keys: Vec<String> = inner_obj
                                .keys()
                                .filter(|k| k.chars().next().is_some_and(|c| c.is_ascii_digit()))
                                .cloned()
                                .collect();
                            if !version_keys.is_empty() {
                                // Sort versions in descending order (newest first)
                                version_keys.sort_by(|a, b| {
                                    compare_versions(b, a)
                                });
                                return version_keys;
                            }
                        }
                        let extracted = extract_auto(val);
                        if !extracted.is_empty() {
                            return extracted;
                        }
                    }
                }
            }
            _ => {}
        }

        results
    }

    fn extract_recursive(json: &serde_json::Value, path: &str, results: &mut Vec<String>) {
        if path.is_empty() {
            // End of path, extract value(s)
            extract_values(json, results);
            return;
        }

        // Handle array iteration "[]"
        if path == "[]" {
            if let Some(arr) = json.as_array() {
                for val in arr {
                    extract_values(val, results);
                }
            }
            return;
        }

        // Handle "[]." prefix (iterate then continue path)
        if let Some(rest) = path.strip_prefix("[].") {
            if let Some(arr) = json.as_array() {
                for val in arr {
                    extract_recursive(val, rest, results);
                }
            }
            return;
        }

        // Handle filter syntax "[?field=value]" or "[?field=value]."
        if let Some(filter_content) = path.strip_prefix("[?") {
            if let Some(end_bracket) = filter_content.find(']') {
                let filter_expr = &filter_content[..end_bracket];
                let rest = &filter_content[end_bracket + 1..];
                let rest = rest.strip_prefix('.').unwrap_or(rest);

                // Parse filter expression "field=value"
                if let Some((filter_field, filter_value)) = filter_expr.split_once('=') {
                    if let Some(arr) = json.as_array() {
                        for val in arr {
                            // Check if this element matches the filter
                            if let Some(obj) = val.as_object() {
                                if let Some(field_val) = obj.get(filter_field) {
                                    if field_val.as_str() == Some(filter_value) {
                                        if rest.is_empty() {
                                            extract_values(val, results);
                                        } else {
                                            extract_recursive(val, rest, results);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return;
        }

        // Handle field access with possible continuation
        // Find where the field name ends (at '.' or '[')
        let (field, rest) = if let Some(idx) = path.find(['.', '[']) {
            let (f, r) = path.split_at(idx);
            // Strip the leading dot if present, but preserve '[' for array handling
            let rest = r.strip_prefix('.').unwrap_or(r);
            (f, rest)
        } else {
            (path, "")
        };

        if let Some(obj) = json.as_object() {
            if let Some(val) = obj.get(field) {
                extract_recursive(val, rest, results);
            }
        }
    }

    fn extract_values(json: &serde_json::Value, results: &mut Vec<String>) {
        match json {
            serde_json::Value::String(s) => {
                let v = normalize_version(s);
                if !v.is_empty() {
                    results.push(v);
                }
            }
            serde_json::Value::Array(arr) => {
                for val in arr {
                    if let Some(s) = val.as_str() {
                        let v = normalize_version(s);
                        if !v.is_empty() {
                            results.push(v);
                        }
                    }
                }
            }
            serde_json::Value::Number(n) => {
                results.push(n.to_string());
            }
            serde_json::Value::Object(obj) => {
                // Try common version field names
                for field in ["version", "tag_name", "name", "tag", "v"] {
                    if let Some(v) = obj.get(field).and_then(|v| v.as_str()) {
                        let v = normalize_version(v);
                        if !v.is_empty() {
                            results.push(v);
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Normalize a version string by trimming whitespace and stripping 'v' prefix
    fn normalize_version(s: &str) -> String {
        s.trim().trim_start_matches('v').to_string()
    }

    /// Compare two version strings for sorting (semver-like comparison)
    /// Returns Ordering for use with sort_by
    fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
        let parse_parts = |v: &str| -> Vec<u64> {
            v.split(|c: char| !c.is_ascii_digit())
                .filter_map(|p| p.parse().ok())
                .collect()
        };

        let a_parts = parse_parts(a);
        let b_parts = parse_parts(b);

        for (a_part, b_part) in a_parts.iter().zip(b_parts.iter()) {
            match a_part.cmp(b_part) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }

        a_parts.len().cmp(&b_parts.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test data from mise registry: dart.toml
    const DART_TOML: &str = r#"
description = "An approachable, portable, and productive language for high-quality apps on any platform"

[[backends]]
full = "http:dart"

[backends.options]
url = "https://storage.googleapis.com/dart-archive/channels/stable/release/{{ version }}/sdk/dartsdk-{{ os() }}-{{ arch() }}-release.zip"
version_list_url = "https://storage.googleapis.com/storage/v1/b/dart-archive/o?prefix=channels/stable/release/&delimiter=/"
version_regex = "channels/stable/release/(\\d+\\.\\d+\\.\\d+)/"

[[backends]]
full = "asdf:mise-plugins/mise-dart"
"#;

    // Test data from mise registry: sentinel.toml (HashiCorp style)
    const SENTINEL_TOML: &str = r#"
description = "Sentinel is a policy as code tool"

[[backends]]
full = "http:sentinel"

[backends.options]
url = 'https://releases.hashicorp.com/sentinel/{{ version }}/sentinel_{{ version }}_{{ os(macos="darwin") }}_{{ arch(x64="amd64") }}.zip'
version_expr = 'fromJSON(body).versions | keys() | sortVersions()'
version_list_url = "https://releases.hashicorp.com/sentinel/index.json"

[[backends]]
full = "asdf:mise-plugins/mise-hashicorp"
"#;

    // ==================== Unit Tests ====================

    #[test]
    fn test_parse_dart_registry() {
        let registry: MiseRegistry = toml::from_str(DART_TOML).unwrap();
        let http_backend = registry
            .backends
            .iter()
            .find(|b| b.full.starts_with("http:"))
            .unwrap();

        assert_eq!(http_backend.full, "http:dart");
        assert_eq!(
            http_backend.options.version_regex,
            Some("channels/stable/release/(\\d+\\.\\d+\\.\\d+)/".to_string())
        );
    }

    #[test]
    fn test_parse_sentinel_registry() {
        let registry: MiseRegistry = toml::from_str(SENTINEL_TOML).unwrap();
        let http_backend = registry
            .backends
            .iter()
            .find(|b| b.full.starts_with("http:"))
            .unwrap();

        assert_eq!(http_backend.full, "http:sentinel");
        assert!(http_backend
            .options
            .url
            .as_ref()
            .unwrap()
            .contains("hashicorp"));
    }

    // ==================== JQ Extraction Tests ====================

    #[test]
    fn test_jq_extract_filter_versions() {
        let data = serde_json::json!({
            "releases": [
                {"version": "3.24.0", "channel": "stable"},
                {"version": "3.25.0-0.1.pre", "channel": "beta"},
                {"version": "3.22.0", "channel": "stable"}
            ]
        });
        let versions = jq::extract(&data, ".releases[?channel=stable].version").unwrap();
        assert_eq!(versions, vec!["3.24.0", "3.22.0"]);
    }

    #[test]
    fn test_jq_extract_nested_field() {
        let data = serde_json::json!({"data": {"version": "1.0.0"}});
        assert_eq!(jq::extract(&data, ".data.version").unwrap(), vec!["1.0.0"]);
    }

    #[test]
    fn test_jq_extract_array_iterate() {
        let data = serde_json::json!(["v1.0.0", "v2.0.0"]);
        assert_eq!(jq::extract(&data, ".[]").unwrap(), vec!["1.0.0", "2.0.0"]);
    }

    #[test]
    fn test_jq_extract_array_field() {
        let data = serde_json::json!([{"version": "1.0.0"}, {"version": "2.0.0"}]);
        assert_eq!(
            jq::extract(&data, ".[].version").unwrap(),
            vec!["1.0.0", "2.0.0"]
        );
    }

    #[test]
    fn test_jq_extract_auto_versions_field() {
        let data = serde_json::json!({"versions": ["v1.0.0", "v2.0.0"]});
        assert_eq!(jq::extract_auto(&data), vec!["1.0.0", "2.0.0"]);
    }

    #[test]
    fn test_jq_extract_auto_releases_field() {
        let data = serde_json::json!({"releases": [{"version": "1.0.0"}, {"version": "2.0.0"}]});
        assert_eq!(jq::extract_auto(&data), vec!["1.0.0", "2.0.0"]);
    }

    #[test]
    fn test_jq_normalize_version() {
        let data = serde_json::json!("v1.2.3");
        assert_eq!(jq::extract(&data, ".").unwrap(), vec!["1.2.3"]);
    }

    // ==================== URL Availability Integration Tests ====================

    /// Test that a nonexistent URL returns false
    #[tokio::test]
    async fn test_check_url_exists_nonexistent() -> Result<()> {
        let client = crate::utils::http::create_client()?;
        let result = check_url_exists(
            &client,
            "https://storage.googleapis.com/this-bucket-does-not-exist-12345/file.zip",
        )
        .await;
        assert!(!result, "Nonexistent URL should return false");
        Ok(())
    }

    /// Test that a valid URL returns true
    #[tokio::test]
    async fn test_check_url_exists_valid() -> Result<()> {
        let client = crate::utils::http::create_client()?;
        // Use a well-known stable URL
        let result = check_url_exists(&client, "https://www.google.com/robots.txt").await;
        assert!(result, "Valid URL should return true");
        Ok(())
    }

    /// Integration test: Full pipeline for Dart
    /// Parse config -> fetch latest version -> render URLs -> check availability
    #[tokio::test]
    async fn test_dart_full_pipeline_with_url_check() -> Result<()> {
        let client = crate::utils::http::create_client()?;

        // Parse config
        let registry: MiseRegistry = toml::from_str(DART_TOML)?;
        let http_backend = registry
            .backends
            .iter()
            .find(|b| b.full.starts_with("http:"))
            .ok_or_else(|| anyhow::anyhow!("no HTTP backend found"))?;

        // Fetch latest version (just like main logic)
        let version = fetch_latest_version(
            &client,
            http_backend.options.version_list_url.as_ref().unwrap(),
            http_backend.options.version_json_path.as_deref(),
            http_backend.options.version_regex.as_deref(),
        )
        .await?;

        // Version should be a valid semver-like string
        assert!(
            version.chars().next().unwrap().is_ascii_digit(),
            "Version should start with digit, got: {}",
            version
        );

        // Check each platform URL availability
        let mut available_platforms = Vec::new();
        for (os, arch) in COMMON_PLATFORMS {
            let url_template = get_platform_url(&http_backend.options, os, arch).unwrap();
            let url = render_url_template(url_template, &version, os, arch)?;

            if check_url_exists(&client, &url).await {
                available_platforms.push(format!("{}-{}", os, arch));
            }
        }

        // Dart should have at least linux-x64 and macos-x64 available
        assert!(
            available_platforms.len() >= 2,
            "Dart should have at least 2 platforms available for version {}, got: {:?}",
            version,
            available_platforms
        );

        // Verify specific platforms that should always be available
        assert!(
            available_platforms.contains(&"linux-x64".to_string()),
            "linux-x64 should be available for Dart, available: {:?}",
            available_platforms
        );
        Ok(())
    }

    /// Integration test: Full pipeline for Sentinel (HashiCorp)
    /// Parse config -> fetch latest version -> render URLs -> check availability
    #[tokio::test]
    async fn test_sentinel_full_pipeline_with_url_check() -> Result<()> {
        let client = crate::utils::http::create_client()?;

        // Parse config
        let registry: MiseRegistry = toml::from_str(SENTINEL_TOML)?;
        let http_backend = registry
            .backends
            .iter()
            .find(|b| b.full.starts_with("http:"))
            .ok_or_else(|| anyhow::anyhow!("no HTTP backend found"))?;

        // Fetch latest version - sentinel uses version_expr which we don't support,
        // so we'll use auto-detection from the JSON response
        let version = fetch_latest_version(
            &client,
            http_backend.options.version_list_url.as_ref().unwrap(),
            http_backend.options.version_json_path.as_deref(),
            http_backend.options.version_regex.as_deref(),
        )
        .await?;

        // Version should be a valid semver-like string
        assert!(
            version.chars().next().unwrap().is_ascii_digit(),
            "Version should start with digit, got: {}",
            version
        );

        // Check macos-x64 (darwin_amd64) - HashiCorp always supports this
        let url_template = get_platform_url(&http_backend.options, "macos", "x64").unwrap();
        let url = render_url_template(url_template, &version, "macos", "x64")?;

        let exists = check_url_exists(&client, &url).await;
        assert!(
            exists,
            "Sentinel darwin_amd64 URL should exist for version {}: {}",
            version, url
        );

        // Check linux-x64 (linux_amd64) - HashiCorp always supports this
        let url_template = get_platform_url(&http_backend.options, "linux", "x64").unwrap();
        let url = render_url_template(url_template, &version, "linux", "x64")?;

        let exists = check_url_exists(&client, &url).await;
        assert!(
            exists,
            "Sentinel linux_amd64 URL should exist for version {}: {}",
            version, url
        );
        Ok(())
    }
}
