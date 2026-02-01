//! Configuration file support for batch mirroring.
//!
//! Config file location: ~/.config/pkg-mrs/config.toml
//!
//! Example config:
//! ```toml
//! [settings]
//! target = "${ALIST_URL}/packages"  # supports env var expansion
//! tool = "aria2"
//!
//! [settings.keepass]
//! db_path = "$HOME/secrets/database.kdbx"  # $VAR or ${VAR} syntax
//! entry_path = "Internet/Alist"
//!
//! [[mirrors]]
//! name = "neovim"
//! regex = "v([0-9.]+)"
//!
//! [mirrors.source.github]
//! repo = "neovim/neovim"
//! asset_filter = "nvim-linux64\\.tar\\.gz$"
//!
//! [[mirrors]]
//! name = "telegram"
//! regex = "([0-9.]+)"
//!
//! [mirrors.source.homebrew]
//! manifest_url = "https://raw.githubusercontent.com/Homebrew/homebrew-cask/master/Casks/t/telegram.rb"
//! arch = "x64"
//! ```

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use keepass::{Database, DatabaseKey, db::Node};
use log::info;
use regex::Regex;
use serde::Deserialize;

/// KeePass configuration for token retrieval.
#[derive(Debug, Deserialize, Clone)]
pub struct KeepassConfig {
    /// Path to KeePass database (.kdbx)
    pub db_path: String,
    /// Entry path inside KeePass (e.g. Internet/Alist)
    pub entry_path: String,
}

/// Global settings that apply to all mirrors.
#[derive(Debug, Deserialize, Default)]
pub struct Settings {
    /// Destination root URL including path prefix (e.g. https://example.com/packages)
    pub target: Option<String>,
    /// Download tool hint (aria2/qbittorrent/transmission)
    #[serde(default = "default_tool")]
    pub tool: String,
    /// KeePass configuration for token retrieval
    pub keepass: Option<KeepassConfig>,
}

fn default_tool() -> String {
    "aria2".to_string()
}

/// GitHub source configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct GithubSource {
    /// GitHub repository (e.g. owner/repo)
    pub repo: String,
    /// Regex pattern to filter assets by filename
    pub asset_filter: Option<String>,
}

/// Homebrew cask/formula source configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct HomebrewSource {
    /// Homebrew formula URL (.rb file)
    pub manifest_url: String,
    /// Architecture filter (e.g. x64, arm64)
    pub arch: Option<String>,
    /// Filename override for destination file
    pub filename: Option<String>,
    /// Language selection for Homebrew manifests
    pub language: Option<String>,
}

/// Scoop manifest source configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct ScoopSource {
    /// Scoop manifest URL (.json file)
    pub manifest_url: String,
    /// Architecture filter (e.g. x64, x86, arm64)
    pub arch: Option<String>,
    /// Filename override for destination file
    pub filename: Option<String>,
}

/// Mise registry source configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct MiseSource {
    /// Mise registry TOML URL
    pub manifest_url: String,
}

/// Mirror source type - GitHub, Homebrew, Scoop, or Mise.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum MirrorSource {
    Github(GithubSource),
    Homebrew(HomebrewSource),
    Scoop(ScoopSource),
    Mise(MiseSource),
}

/// A mirror configuration entry.
#[derive(Debug, Deserialize, Clone)]
pub struct MirrorConfig {
    /// Package name (used in destination path hierarchy)
    pub name: String,
    /// Regex pattern to extract version (uses first capture group)
    pub regex: String,
    /// Source configuration (github, homebrew, or scoop)
    pub source: MirrorSource,
    /// Override target URL for this mirror
    pub target: Option<String>,
    /// Override tool for this mirror
    pub tool: Option<String>,
}

/// Root configuration structure.
#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub mirrors: Vec<MirrorConfig>,
}

impl Config {
    /// Get the default config file path: ~/.config/pkg-mrs/config.toml
    pub fn default_path() -> Result<PathBuf> {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        Ok(PathBuf::from(home)
            .join(".config")
            .join("pkg-mrs")
            .join("config.toml"))
    }

    /// Load configuration from the default path.
    pub fn load() -> Result<Self> {
        let path = Self::default_path()?;
        Self::load_from(&path)
    }

    /// Load configuration from a specific path.
    pub fn load_from(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            bail!(
                "config file not found: {}\n\nCreate a config file or use subcommands directly.\nRun with --help for usage.",
                path.display()
            );
        }

        info!("Loading config from: {}", path.display());
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file: {}", path.display()))?;

        // Expand environment variables in the config content
        let expanded_content = expand_env_vars(&content);

        let config: Config =
            toml::from_str(&expanded_content).with_context(|| "parsing config file as TOML")?;

        Ok(config)
    }

    /// Get the token from KeePass database.
    pub fn get_token(&self) -> Result<String> {
        let keepass_config = self
            .settings
            .keepass
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no keepass configuration in [settings.keepass]"))?;

        let password = std::env::var("KEEPASS_PASSWORD")
            .context("KEEPASS_PASSWORD environment variable not set")?;

        info!("Opening KeePass database: {}", keepass_config.db_path);
        let file = File::open(&keepass_config.db_path)
            .with_context(|| format!("opening KeePass database: {}", keepass_config.db_path))?;

        let key = DatabaseKey::new().with_password(&password);
        let db = Database::open(&mut BufReader::new(file), key)
            .context("opening KeePass database (wrong password?)")?;

        let token = lookup_entry(&db, &keepass_config.entry_path)?;
        info!("Retrieved token from KeePass entry: {}", keepass_config.entry_path);

        Ok(token)
    }

    /// Get the effective target URL.
    pub fn get_target(&self) -> Result<String> {
        self.settings
            .target
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no target URL configured in [settings]"))
    }
}

/// Expand environment variables in a string.
/// Supports both `${VAR}` and `$VAR` syntax.
/// If an environment variable is not set, it is replaced with an empty string.
fn expand_env_vars(content: &str) -> String {
    // Match ${VAR} or $VAR patterns
    // ${VAR} - braced form, allows special characters in var name
    // $VAR - simple form, var name is alphanumeric + underscore
    let re = Regex::new(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)").unwrap();

    re.replace_all(content, |caps: &regex::Captures| {
        // Try braced form first (group 1), then simple form (group 2)
        let var_name = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");

        std::env::var(var_name).unwrap_or_default()
    })
    .to_string()
}

/// Lookup an entry in the KeePass database and return its password.
fn lookup_entry(db: &Database, path: &str) -> Result<String> {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        bail!("empty entry path specified");
    }

    let mut group = &db.root;
    for (i, part) in parts.iter().enumerate() {
        let is_last = i == parts.len() - 1;
        if is_last {
            // Search for entry
            for node in &group.children {
                if let Node::Entry(e) = node
                    && e.get_title().map(|t| t == *part).unwrap_or(false)
                {
                    return e
                        .get_password()
                        .map(|s| s.to_string())
                        .ok_or_else(|| anyhow::anyhow!("entry has no password: {}", path));
                }
            }
            bail!("entry not found: {}", path);
        } else {
            // Descend into subgroup
            let mut found = None;
            for node in &group.children {
                if let Node::Group(g) = node
                    && g.name == *part
                {
                    found = Some(g);
                    break;
                }
            }

            if let Some(g) = found {
                group = g;
            } else {
                bail!("group not found: {}", part);
            }
        }
    }

    bail!("unexpected traversal termination for {}", path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let content = r#"
[settings]
target = "https://example.com/packages"
tool = "aria2"

[settings.keepass]
db_path = "/path/to/db.kdbx"
entry_path = "Internet/Alist"

[[mirrors]]
name = "neovim"
regex = "v([0-9.]+)"

[mirrors.source.github]
repo = "neovim/neovim"
asset_filter = "nvim-linux64\\.tar\\.gz$"

[[mirrors]]
name = "telegram"
regex = "([0-9.]+)"

[mirrors.source.homebrew]
manifest_url = "https://example.com/telegram.rb"
arch = "x64"

[[mirrors]]
name = "firefox"
regex = "([0-9.]+)"

[mirrors.source.scoop]
manifest_url = "https://example.com/firefox.json"
arch = "x64"
"#;
        let config: Config = toml::from_str(content).unwrap();
        assert_eq!(config.settings.target, Some("https://example.com/packages".to_string()));
        assert_eq!(config.settings.tool, "aria2");
        assert!(config.settings.keepass.is_some());
        assert_eq!(config.mirrors.len(), 3);

        assert_eq!(config.mirrors[0].name, "neovim");
        match &config.mirrors[0].source {
            MirrorSource::Github(gh) => {
                assert_eq!(gh.repo, "neovim/neovim");
            }
            _ => panic!("expected github source"),
        }

        assert_eq!(config.mirrors[1].name, "telegram");
        match &config.mirrors[1].source {
            MirrorSource::Homebrew(hb) => {
                assert_eq!(hb.manifest_url, "https://example.com/telegram.rb");
                assert_eq!(hb.arch, Some("x64".to_string()));
            }
            _ => panic!("expected homebrew source"),
        }

        assert_eq!(config.mirrors[2].name, "firefox");
        match &config.mirrors[2].source {
            MirrorSource::Scoop(sc) => {
                assert_eq!(sc.manifest_url, "https://example.com/firefox.json");
                assert_eq!(sc.arch, Some("x64".to_string()));
            }
            _ => panic!("expected scoop source"),
        }
    }

    #[test]
    fn test_expand_env_vars() {
        // Set test env vars
        // SAFETY: This test runs in isolation and we clean up the env vars at the end
        unsafe {
            std::env::set_var("TEST_PKG_MRS_VAR", "hello");
            std::env::set_var("TEST_PKG_MRS_URL", "https://example.com");
        }

        // Test ${VAR} syntax
        assert_eq!(
            expand_env_vars("value is ${TEST_PKG_MRS_VAR}"),
            "value is hello"
        );

        // Test $VAR syntax
        assert_eq!(
            expand_env_vars("value is $TEST_PKG_MRS_VAR"),
            "value is hello"
        );

        // Test multiple vars
        assert_eq!(
            expand_env_vars("${TEST_PKG_MRS_URL}/path/$TEST_PKG_MRS_VAR"),
            "https://example.com/path/hello"
        );

        // Test undefined var (should become empty)
        assert_eq!(
            expand_env_vars("${UNDEFINED_VAR_12345}"),
            ""
        );

        // Test no vars
        assert_eq!(
            expand_env_vars("no variables here"),
            "no variables here"
        );

        // Cleanup
        // SAFETY: Cleaning up test env vars
        unsafe {
            std::env::remove_var("TEST_PKG_MRS_VAR");
            std::env::remove_var("TEST_PKG_MRS_URL");
        }
    }

    #[test]
    fn test_parse_config_with_env_vars() {
        // Set test env vars
        // SAFETY: This test runs in isolation and we clean up the env vars at the end
        unsafe {
            std::env::set_var("TEST_TARGET_HOST", "https://myhost.com");
            std::env::set_var("TEST_KDBX_PATH", "/home/user/secrets");
            std::env::set_var("TEST_GH_REPO", "owner/repo");
        }

        let content = r#"
[settings]
target = "${TEST_TARGET_HOST}/packages"
tool = "aria2"

[settings.keepass]
db_path = "$TEST_KDBX_PATH/db.kdbx"
entry_path = "Internet/Alist"

[[mirrors]]
name = "myapp"
regex = "v([0-9.]+)"

[mirrors.source.github]
repo = "$TEST_GH_REPO"
"#;

        let expanded = expand_env_vars(content);
        let config: Config = toml::from_str(&expanded).unwrap();

        assert_eq!(config.settings.target, Some("https://myhost.com/packages".to_string()));
        assert_eq!(
            config.settings.keepass.as_ref().unwrap().db_path,
            "/home/user/secrets/db.kdbx"
        );

        match &config.mirrors[0].source {
            MirrorSource::Github(gh) => {
                assert_eq!(gh.repo, "owner/repo");
            }
            _ => panic!("expected github source"),
        }

        // Cleanup
        // SAFETY: Cleaning up test env vars
        unsafe {
            std::env::remove_var("TEST_TARGET_HOST");
            std::env::remove_var("TEST_KDBX_PATH");
            std::env::remove_var("TEST_GH_REPO");
        }
    }
}
