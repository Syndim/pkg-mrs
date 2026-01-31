//! Alist API client for file operations and offline downloads.

use anyhow::{Context, Result, bail};
use log::info;
use percent_encoding::percent_decode_str;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde_json::Value;

use crate::cli::CHROME_UA;

/// Parse target URL to extract origin and root path.
pub fn parse_target(target: &str) -> Result<(String, String)> {
    let trimmed = target.trim_end_matches('/');
    let scheme_split = trimmed.splitn(2, "://").collect::<Vec<_>>();

    if scheme_split.len() != 2 {
        bail!("target must include scheme (e.g. https://host/path)");
    }

    let scheme = scheme_split[0];
    let rest = scheme_split[1];
    let first_slash = rest.find('/').ok_or_else(|| {
        anyhow::anyhow!("target must include path segment after host (e.g. https://host/prefix)")
    })?;

    let host = &rest[..first_slash];
    let path = &rest[first_slash..];

    if !path.starts_with('/') {
        bail!("parsed path does not start with '/' in target");
    }

    Ok((format!("{}://{}", scheme, host), path.to_string()))
}

/// Check if a file exists at the given path in alist.
pub async fn file_exists(
    client: &reqwest::Client,
    origin: &str,
    token: &str,
    path: &str,
) -> Result<bool> {
    let get_url = format!("{}/api/fs/get", origin);
    let body = serde_json::json!({"path": path});

    let resp = client
        .post(&get_url)
        .header(USER_AGENT, CHROME_UA)
        .header(AUTHORIZATION, token)
        .json(&body)
        .send()
        .await
        .context("querying file status")?;

    let status_code = resp.status().as_u16();
    let body_text = resp.text().await.unwrap_or_default();

    let parsed = serde_json::from_str::<Value>(&body_text).ok();
    let api_code = parsed
        .as_ref()
        .and_then(|v| v.get("code").and_then(|c| c.as_i64()))
        .unwrap_or(-1);

    info!(
        "file_exists check path={} http_status={} api_code={}",
        path, status_code, api_code
    );

    if status_code == 401 {
        bail!("unauthorized querying file status (invalid token?)");
    }

    if status_code == 200 && api_code == 200 {
        return Ok(true);
    }

    if status_code == 404 || api_code != 200 {
        return Ok(false);
    }

    bail!("unexpected status {} checking file existence", status_code)
}

/// Create an offline download task in alist.
pub async fn create_offline_download_task(
    client: &reqwest::Client,
    origin: &str,
    token: &str,
    url: &str,
    dest_dir: &str,
    tool: &str,
) -> Result<()> {
    let add_url = format!("{}/api/fs/add_offline_download", origin);
    let body = serde_json::json!({
        "delete_policy": "delete_on_upload_succeed",
        "path": dest_dir.trim_end_matches('/'),
        "urls": [url],
        "tool": tool,
    });

    info!("Submitting offline download task");
    let resp = client
        .post(&add_url)
        .header(USER_AGENT, CHROME_UA)
        .header(AUTHORIZATION, token)
        .header(CONTENT_TYPE, "application/json")
        .json(&body)
        .send()
        .await
        .with_context(|| format!("creating offline download task at {}", add_url))?;

    if !resp.status().is_success() {
        bail!(
            "offline download task creation failed with status {}",
            resp.status()
        );
    }

    let text = resp.text().await.unwrap_or_default();
    info!("Task creation response: {}", text);

    let resp_json: Value = serde_json::from_str(&text)
        .with_context(|| format!("parsing offline download task creation JSON: {}", text))?;

    let api_code = resp_json.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
    if api_code != 200 {
        bail!(
            "offline download task creation returned code {} (expected 200)",
            api_code
        );
    }

    Ok(())
}

/// Normalize and join path segments ensuring proper format.
pub fn normalize_join(base: &str, extra: &str) -> String {
    let base = base.trim_end_matches('/');
    let extra = extra.trim_start_matches('/').trim_end_matches('/');

    let joined = if extra.is_empty() {
        base.to_string()
    } else {
        format!("{}/{}", base, extra)
    };

    // Ensure it starts with / and ends with /
    let result = if joined.starts_with('/') {
        joined
    } else {
        format!("/{}", joined)
    };

    format!("{}/", result)
}

/// URL-decode a percent-encoded string.
pub fn url_unescape(input: &str) -> String {
    percent_decode_str(input)
        .decode_utf8()
        .map(|c| c.to_string())
        .unwrap_or_else(|_| input.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target() {
        let (origin, path) = parse_target("https://fox.oplist.org.cn/packages").unwrap();
        assert_eq!(origin, "https://fox.oplist.org.cn");
        assert_eq!(path, "/packages");
    }

    #[test]
    fn test_normalize_join() {
        assert_eq!(normalize_join("/base", "extra"), "/base/extra/");
        assert_eq!(normalize_join("/base/", "/extra"), "/base/extra/");
        assert_eq!(normalize_join("base", "extra"), "/base/extra/");
        assert_eq!(normalize_join("/base", ""), "/base/");
    }
}
