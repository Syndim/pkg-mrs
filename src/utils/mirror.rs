//! Mirror/download task utilities.

use anyhow::Result;
use log::info;

use crate::alist::{self, url_unescape};

/// Mirror a single file to Alist storage.
/// Returns true if the file was mirrored, false if it already exists.
///
/// The `log_prefix` is used in log messages (e.g., "[linux-x64] Destination: ...").
pub async fn mirror_file(
    client: &reqwest::Client,
    origin: &str,
    token: &str,
    source_url: &str,
    root_path: &str,
    package_name: &str,
    version: &str,
    filename: &str,
    tool: &str,
    log_prefix: &str,
) -> Result<bool> {
    let dest_dir = alist::normalize_join(root_path, &format!("{}/{}/", package_name, version));
    let dest_file_path = format!("{}{}", dest_dir, filename);
    let unescaped_dest_file_path = url_unescape(&dest_file_path);

    info!("[{}] Destination: {}", log_prefix, unescaped_dest_file_path);

    // Check if file already exists
    if alist::file_exists(client, origin, token, &unescaped_dest_file_path).await? {
        info!("[{}] File already exists, skipping", log_prefix);
        return Ok(false);
    }

    // Create offline download task
    alist::create_offline_download_task(client, origin, token, source_url, &dest_dir, tool).await?;

    info!("[{}] Offline download task created", log_prefix);
    Ok(true)
}
