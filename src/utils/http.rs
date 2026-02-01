//! HTTP client utilities.

use anyhow::{Context, Result};

use crate::cli::CHROME_UA;

/// Create a new reqwest HTTP client with standard user agent.
pub fn create_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(CHROME_UA)
        .build()
        .context("building reqwest client")
}
