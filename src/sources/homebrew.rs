//! Homebrew/Scoop manifest mirror source.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use clap::Args;
use log::info;
use reqwest::header::USER_AGENT;
use serde::Deserialize;

use crate::alist::{self, url_unescape};
use crate::cli::{CHROME_UA, CommonArgs};

#[derive(Args, Debug)]
pub struct HomebrewArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Homebrew formula URL (e.g. https://raw.githubusercontent.com/.../formula.rb) or Scoop manifest URL
    #[arg(long)]
    pub manifest_url: String,

    /// Optional architecture filter (e.g. x64, arm64). If not provided, mirrors all architectures
    #[arg(long)]
    pub arch: Option<String>,

    /// Optional filename to use for the destination file (overrides filename from URL)
    #[arg(long)]
    pub filename: Option<String>,

    /// Optional language to select from language blocks in Homebrew manifests (e.g. zh-CN, en-US)
    #[arg(long)]
    pub language: Option<String>,
}

#[derive(Debug, Clone)]
struct PackageUrl {
    url: String,
    version: String,
    arch: String,
}

/// Represents a property value in Homebrew manifest
#[derive(Debug, Clone)]
enum PropertyValue {
    /// Simple string value: version "1.2.3"
    String(String),
    /// Dict value: arch arm: "aarch64", intel: "x86_64"
    Dict(HashMap<String, String>),
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
    #[allow(dead_code)]
    #[serde(rename = "32bit")]
    x86: Option<ScoopArchData>,
    #[allow(dead_code)]
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

impl PropertyValue {
    /// Apply a method call to the property value
    fn apply_method(&self, method_chain: &[&str]) -> Option<String> {
        match self {
            PropertyValue::String(s) => {
                let mut result = s.clone();

                // Handle method chain like ["csv", "first"] or ["csv", "second"]
                let mut i = 0;
                while i < method_chain.len() {
                    match method_chain[i] {
                        "csv" => {
                            // Next element should be "first" or "second"
                            if i + 1 < method_chain.len() {
                                match method_chain[i + 1] {
                                    "first" => {
                                        result =
                                            result.split(',').next().unwrap_or(&result).to_string();
                                        i += 2;
                                    }
                                    "second" => {
                                        result = result.split(',').nth(1).unwrap_or("").to_string();
                                        i += 2;
                                    }
                                    _ => i += 1,
                                }
                            } else {
                                i += 1;
                            }
                        }
                        _ => i += 1,
                    }
                }

                Some(result)
            }

            PropertyValue::Dict(_) => None,
        }
    }
}

pub fn handle(args: HomebrewArgs) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async_handle(args))
}

async fn async_handle(args: HomebrewArgs) -> Result<()> {
    let (origin, root_path) = alist::parse_target(&args.common.target)?;
    let token = &args.common.token;

    if token.trim().is_empty() {
        bail!("alist token is empty");
    }

    info!("Retrieved token for alist");

    let client = reqwest::Client::builder()
        .user_agent(CHROME_UA)
        .build()
        .context("building reqwest client")?;

    // Fetch and parse manifest to get download URLs
    info!("Fetching manifest from: {}", args.manifest_url);
    let mut package_urls =
        fetch_and_parse_manifest(&client, &args.manifest_url, args.language.as_deref()).await?;

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
            extract_version(&pkg.url, &args.common.regex).unwrap_or_else(|| {
                info!(
                    "Failed to extract version from URL using regex, falling back to manifest version: {}",
                    pkg.version
                );
                pkg.version.clone()
            });

        info!("Mirroring {} {}", args.common.name, version_for_path);

        let filename = determine_filename(
            args.filename.as_deref(),
            &pkg.url,
            &args.common.name,
            &version_for_path,
        );

        let dest_dir = alist::normalize_join(
            &root_path,
            &format!("{}/{}/", args.common.name, version_for_path),
        );
        let dest_file_path = format!("{}{}", dest_dir, filename);
        let unescaped_dest_file_path = url_unescape(&dest_file_path);

        info!("Destination: {}", unescaped_dest_file_path);

        // Check if file already exists
        if alist::file_exists(&client, &origin, token, &unescaped_dest_file_path).await? {
            info!("File already exists, skipping");
            continue;
        }

        // Create offline download task
        alist::create_offline_download_task(
            &client,
            &origin,
            token,
            &pkg.url,
            &dest_dir,
            &args.common.tool,
        )
        .await?;

        info!("Offline download task created successfully");
    }

    info!("All offline download tasks submitted successfully");
    Ok(())
}

async fn fetch_and_parse_manifest(
    client: &reqwest::Client,
    manifest_url: &str,
    preferred_language: Option<&str>,
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

    // Detect manifest type and parse accordingly
    if manifest_url.ends_with(".json") {
        parse_scoop_manifest(&content)
    } else if manifest_url.ends_with(".rb") {
        parse_homebrew_manifest(&content, preferred_language)
    } else {
        bail!(
            "unknown manifest format (expected .json for Scoop or .rb for Homebrew): {manifest_url}"
        );
    }
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

    // Extract 64bit architecture if present
    if let Some(arch) = manifest.architecture
        && let Some(x64_data) = arch.x64
        && let Some(urls_from_arch) = extract_urls_from_arch_data(&x64_data)
    {
        for url in urls_from_arch {
            urls.push(PackageUrl {
                url,
                version: version.clone(),
                arch: "x64".to_string(),
            });
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

fn parse_homebrew_manifest(
    content: &str,
    preferred_language: Option<&str>,
) -> Result<Vec<PackageUrl>> {
    // Extract all properties from the manifest
    let properties = extract_properties(content, preferred_language);

    // Get version (required)
    let version = properties
        .get("version")
        .and_then(|v| match v {
            PropertyValue::String(s) => Some(s.clone()),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("version not found in Homebrew manifest"))?;

    let mut urls = Vec::new();

    // Parse bottle section for different platforms
    let bottle_regex = regex::Regex::new(
        r#"(arm64_\w+|x86_64_\w+|monterey|ventura|sonoma|linux|all):\s*"[^"]+"\s*url\s+"([^"]+)""#,
    )
    .context("compiling bottle regex")?;

    // Try to find bottle URLs with platform info
    for caps in bottle_regex.captures_iter(content) {
        let platform_str = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let url = caps.get(2).map(|m| m.as_str()).unwrap_or("");

        // Infer arch from platform string (arm64_* -> arm64, otherwise x64)
        let arch = if platform_str.to_lowercase().contains("arm64") {
            "arm64".to_string()
        } else {
            "x64".to_string()
        };

        urls.push(PackageUrl {
            url: url.to_string(),
            version: version.clone(),
            arch,
        });
    }

    // If no bottle URLs found, look for generic URLs
    if urls.is_empty() {
        // Use the URL from properties (already extracted with proper nesting depth handling)
        if let Some(PropertyValue::String(url_template)) = properties.get("url") {
            // Log selected language if URL contains #{language}
            if url_template.contains("#{language}")
                && let Some(PropertyValue::String(lang)) = properties.get("language")
            {
                info!("Selected language: {}", lang);
            }

            // Expand the URL template and generate URLs for all arch variants
            urls.extend(expand_url_template(url_template, &properties, &version)?);
        }
    }

    if urls.is_empty() {
        bail!("no URLs found in Homebrew manifest");
    }

    Ok(urls)
}

/// Extract all properties from Homebrew manifest
///
/// Uses a state machine parser to handle:
/// - Simple string properties: `version "1.2.3"`
/// - Single-line dicts: `arch arm: "aarch64", intel: "x86_64"`
/// - Multi-line dicts with continuation
/// - Nested blocks (do...end, begin...end)
/// - Language selection blocks
fn extract_properties(
    content: &str,
    preferred_language: Option<&str>,
) -> HashMap<String, PropertyValue> {
    // Common state properties shared across most states
    #[derive(Debug, Clone)]
    struct CommonState {
        depth: usize,
        selected_language: String,
        selected_priority: u8,
        conditional_block_priority: i8, // 2 = :or_newer, 0 = none, -1 = :or_older
        in_ignored_block: bool,         // true if inside livecheck/zap/uninstall blocks
    }

    // Language block specific properties
    #[derive(Debug, Clone)]
    struct LanguageBlockState {
        common: CommonState,
        candidate_code: String,
        candidate_priority: u8,
        candidate_value: Option<String>,
        is_default: bool,
    }

    // Property parsing specific properties
    #[derive(Debug, Clone)]
    struct PropertyState {
        common: CommonState,
        name: String,
        accumulated: String,
    }

    #[derive(Debug, Clone)]
    enum State {
        AtDepth(CommonState),
        InNestedBlock(CommonState),
        InLanguageBlock(LanguageBlockState),
        InProperty(PropertyState),
    }

    struct ParserContext<'a> {
        properties: HashMap<String, PropertyValue>,
        keywords: &'a [&'a str],
        target_depth: usize,
        pair_regex: regex::Regex,
        property_start_regex: regex::Regex,
        bare_string_regex: regex::Regex,
        version_priority: i8,
        preferred_language: Option<&'a str>,
    }

    /// Handle state transitions for AtDepth and InNestedBlock states
    fn handle_at_depth_or_nested_block(
        ctx: &ParserContext,
        trimmed: &str,
        common: CommonState,
    ) -> State {
        // Check if we're starting a language block
        if trimmed.starts_with("language ")
            && trimmed.ends_with(" do")
            && let Some(lang_code) = extract_language_code(trimmed)
        {
            let priority = get_language_priority(&lang_code);
            let is_default = is_default_language(trimmed);
            return State::InLanguageBlock(LanguageBlockState {
                common: CommonState {
                    depth: common.depth + 1,
                    selected_language: common.selected_language,
                    selected_priority: common.selected_priority,
                    conditional_block_priority: common.conditional_block_priority,
                    in_ignored_block: common.in_ignored_block,
                },
                candidate_code: lang_code,
                candidate_priority: priority,
                candidate_value: None,
                is_default,
            });
        }

        // Check if we're entering an ignored block (livecheck, zap, uninstall, etc.)
        let entering_ignored_block = trimmed.starts_with("livecheck ")
            || trimmed.starts_with("zap ")
            || trimmed.starts_with("uninstall ")
            || trimmed.starts_with("postflight ")
            || trimmed.starts_with("preflight ")
            || trimmed.starts_with("installer ");

        // Check if we're entering a conditional block
        let block_priority = if trimmed.contains(":or_newer") {
            2
        } else if trimmed.contains(":or_older") {
            -1
        } else {
            common.conditional_block_priority
        };

        // Check if we're entering a nested block
        if trimmed.ends_with(" do")
            || trimmed.ends_with(" begin")
            || trimmed == "do"
            || trimmed == "begin"
        {
            return State::InNestedBlock(CommonState {
                depth: common.depth + 1,
                selected_language: common.selected_language,
                selected_priority: common.selected_priority,
                conditional_block_priority: block_priority,
                in_ignored_block: common.in_ignored_block || entering_ignored_block,
            });
        }

        // Check if we're exiting a block
        if trimmed == "end" {
            let new_depth = if common.depth > 0 {
                common.depth - 1
            } else {
                0
            };

            let new_common = CommonState {
                depth: new_depth,
                selected_language: common.selected_language,
                selected_priority: common.selected_priority,
                conditional_block_priority: 0,
                in_ignored_block: if new_depth == ctx.target_depth {
                    false
                } else {
                    common.in_ignored_block
                },
            };

            return if new_depth == ctx.target_depth {
                State::AtDepth(new_common)
            } else {
                State::InNestedBlock(new_common)
            };
        }

        // Skip property extraction if we're in an ignored block
        if common.in_ignored_block {
            return State::InNestedBlock(common);
        }

        // At target depth OR in nested block, check if this starts a property
        let starts_new_property = if let Some(first_word) = trimmed.split_whitespace().next() {
            !ctx.keywords.contains(&first_word) && !first_word.ends_with(':')
        } else {
            false
        };

        if starts_new_property && let Some(caps) = ctx.property_start_regex.captures(trimmed) {
            let prop_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            return State::InProperty(PropertyState {
                common,
                name: prop_name.to_string(),
                accumulated: trimmed.to_string(),
            });
        }

        // Return appropriate state based on depth
        if common.depth == ctx.target_depth {
            State::AtDepth(common)
        } else {
            State::InNestedBlock(common)
        }
    }

    /// Handle state transitions for InLanguageBlock state
    fn handle_in_language_block(
        ctx: &ParserContext,
        trimmed: &str,
        mut lang_state: LanguageBlockState,
    ) -> State {
        // Inside a language block, look for bare strings
        if let Some(caps) = ctx.bare_string_regex.captures(trimmed) {
            let string_val = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            lang_state.candidate_value = Some(string_val.to_string());
        }

        // Check if we're closing the language block
        if trimmed == "end" {
            let new_depth = if lang_state.common.depth > 0 {
                lang_state.common.depth - 1
            } else {
                0
            };

            // Decide whether to adopt this language
            let (final_language, final_priority) = if let Some(preferred) = ctx.preferred_language {
                // If user specified a preferred language, use it if it matches
                if lang_state.candidate_code == preferred {
                    let lang_to_use = lang_state
                        .candidate_value
                        .unwrap_or(lang_state.candidate_code);
                    (lang_to_use, 255) // Highest priority for user-specified language
                } else {
                    (
                        lang_state.common.selected_language,
                        lang_state.common.selected_priority,
                    )
                }
            } else {
                // No preferred language specified by user
                if lang_state.is_default && lang_state.common.selected_priority < 100 {
                    let lang_to_use = lang_state
                        .candidate_value
                        .unwrap_or(lang_state.candidate_code);
                    (lang_to_use, 100)
                } else if lang_state.candidate_priority > lang_state.common.selected_priority
                    && lang_state.common.selected_priority < 100
                {
                    let lang_to_use = lang_state
                        .candidate_value
                        .unwrap_or(lang_state.candidate_code);
                    (lang_to_use, lang_state.candidate_priority)
                } else {
                    (
                        lang_state.common.selected_language,
                        lang_state.common.selected_priority,
                    )
                }
            };

            let new_common = CommonState {
                depth: new_depth,
                selected_language: final_language,
                selected_priority: final_priority,
                conditional_block_priority: lang_state.common.conditional_block_priority,
                in_ignored_block: lang_state.common.in_ignored_block,
            };

            return if new_depth == ctx.target_depth {
                State::AtDepth(new_common)
            } else {
                State::InNestedBlock(new_common)
            };
        }

        // Stay in language block
        State::InLanguageBlock(lang_state)
    }

    /// Handle state transitions for InProperty state
    fn handle_in_property(
        ctx: &mut ParserContext,
        trimmed: &str,
        prop_state: PropertyState,
    ) -> State {
        // Handle block depth changes
        if trimmed.ends_with(" do")
            || trimmed.ends_with(" begin")
            || trimmed == "do"
            || trimmed == "begin"
        {
            // Finalize current property
            finalize_property(
                &mut ctx.properties,
                &prop_state.name,
                &prop_state.accumulated,
                &ctx.pair_regex,
                prop_state.common.conditional_block_priority,
                &mut ctx.version_priority,
            );

            let entering_ignored_block = trimmed.starts_with("livecheck ")
                || trimmed.starts_with("zap ")
                || trimmed.starts_with("uninstall ")
                || trimmed.starts_with("postflight ")
                || trimmed.starts_with("preflight ")
                || trimmed.starts_with("installer ");

            return State::InNestedBlock(CommonState {
                depth: prop_state.common.depth + 1,
                selected_language: prop_state.common.selected_language,
                selected_priority: prop_state.common.selected_priority,
                conditional_block_priority: prop_state.common.conditional_block_priority,
                in_ignored_block: prop_state.common.in_ignored_block || entering_ignored_block,
            });
        }

        if trimmed == "end" {
            finalize_property(
                &mut ctx.properties,
                &prop_state.name,
                &prop_state.accumulated,
                &ctx.pair_regex,
                prop_state.common.conditional_block_priority,
                &mut ctx.version_priority,
            );

            let new_depth = if prop_state.common.depth > 0 {
                prop_state.common.depth - 1
            } else {
                0
            };

            let new_common = CommonState {
                depth: new_depth,
                selected_language: prop_state.common.selected_language,
                selected_priority: prop_state.common.selected_priority,
                conditional_block_priority: 0,
                in_ignored_block: false,
            };

            return if new_depth == ctx.target_depth {
                State::AtDepth(new_common)
            } else {
                State::InNestedBlock(new_common)
            };
        }

        // Check if this starts a new property
        let starts_new_property = if let Some(first_word) = trimmed.split_whitespace().next() {
            !ctx.keywords.contains(&first_word) && !first_word.ends_with(':')
        } else {
            false
        };

        if starts_new_property {
            finalize_property(
                &mut ctx.properties,
                &prop_state.name,
                &prop_state.accumulated,
                &ctx.pair_regex,
                prop_state.common.conditional_block_priority,
                &mut ctx.version_priority,
            );

            if prop_state.common.in_ignored_block {
                return State::InNestedBlock(prop_state.common);
            }

            if let Some(caps) = ctx.property_start_regex.captures(trimmed) {
                let prop_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                return State::InProperty(PropertyState {
                    common: prop_state.common,
                    name: prop_name.to_string(),
                    accumulated: trimmed.to_string(),
                });
            } else {
                return State::AtDepth(prop_state.common);
            }
        }

        // Continuation line - accumulate it
        let mut new_accumulated = prop_state.accumulated;
        new_accumulated.push(' ');
        new_accumulated.push_str(trimmed);

        State::InProperty(PropertyState {
            common: prop_state.common,
            name: prop_state.name,
            accumulated: new_accumulated,
        })
    }

    let mut ctx = ParserContext {
        properties: HashMap::new(),
        keywords: &[
            "do", "end", "if", "unless", "case", "when", "cask", "class", "def", "module", "else",
            "elsif", "begin", "rescue", "ensure", "while", "until", "for", "in", "return", "yield",
            "break", "next", "redo", "retry", "raise", "super", "self", "true", "false", "nil",
            "and", "or", "not",
        ],
        target_depth: if content.contains("cask ") { 1 } else { 0 },
        pair_regex: regex::Regex::new(r#"(\w+):\s*"([^"]+)""#).unwrap(),
        property_start_regex: regex::Regex::new(r#"^(\w+)\s+"#).unwrap(),
        bare_string_regex: regex::Regex::new(r#"^"([^"]+)"$"#).unwrap(),
        version_priority: i8::MIN,
        preferred_language,
    };

    let lines: Vec<&str> = content.lines().collect();
    let mut state = State::AtDepth(CommonState {
        depth: 0,
        selected_language: "en".to_string(),
        selected_priority: 1,
        conditional_block_priority: 0,
        in_ignored_block: false,
    });

    for line in lines {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        state = match state {
            State::AtDepth(common) | State::InNestedBlock(common) => {
                handle_at_depth_or_nested_block(&ctx, trimmed, common)
            }
            State::InLanguageBlock(lang_state) => {
                handle_in_language_block(&ctx, trimmed, lang_state)
            }
            State::InProperty(prop_state) => handle_in_property(&mut ctx, trimmed, prop_state),
        };
    }

    // Finalize any remaining property
    if let State::InProperty(prop_state) = &state {
        finalize_property(
            &mut ctx.properties,
            &prop_state.name,
            &prop_state.accumulated,
            &ctx.pair_regex,
            prop_state.common.conditional_block_priority,
            &mut ctx.version_priority,
        );
    }

    // Store the selected language as a property
    let final_language = match &state {
        State::AtDepth(common)
        | State::InNestedBlock(common)
        | State::InProperty(PropertyState { common, .. }) => common.selected_language.clone(),
        State::InLanguageBlock(lang_state) => lang_state.common.selected_language.clone(),
    };

    ctx.properties.insert(
        "language".to_string(),
        PropertyValue::String(final_language),
    );

    ctx.properties
}

/// Finalize a property by determining if it's a dict or string and adding it to the map
fn finalize_property(
    properties: &mut HashMap<String, PropertyValue>,
    name: &str,
    accumulated: &str,
    pair_regex: &regex::Regex,
    conditional_block_priority: i8,
    version_priority: &mut i8,
) {
    // Try to parse as simple string property first
    let string_prop_regex = regex::Regex::new(r#"^\w+\s+"([^"]+)""#).unwrap();
    if let Some(caps) = string_prop_regex.captures(accumulated) {
        let value = caps.get(1).map(|m| m.as_str()).unwrap_or("");

        // Special handling for version: only update if priority is higher
        if name == "version" {
            if conditional_block_priority > *version_priority {
                properties.insert(name.to_string(), PropertyValue::String(value.to_string()));
                *version_priority = conditional_block_priority;
            }
        } else {
            properties.insert(name.to_string(), PropertyValue::String(value.to_string()));
        }
        return;
    }

    // Try to parse as dict (has key:value pairs) only if string parsing failed
    let pairs: HashMap<String, String> = pair_regex
        .captures_iter(accumulated)
        .map(|caps| {
            let k = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let v = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
            (k, v)
        })
        .collect();

    if !pairs.is_empty() {
        properties.insert(name.to_string(), PropertyValue::Dict(pairs));
    }
}

/// Extract language code from a language block line
fn extract_language_code(line: &str) -> Option<String> {
    let re = regex::Regex::new(r#"language\s+"([^"]+)""#).ok()?;
    re.captures(line)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

/// Check if a language line has default: true
fn is_default_language(line: &str) -> bool {
    line.contains("default:") && line.contains("true")
}

/// Get priority for language selection
fn get_language_priority(lang: &str) -> u8 {
    match lang {
        "zh-CN" => 4,
        "zh" => 3,
        "en-US" => 2,
        "en" => 1,
        _ => 0,
    }
}

/// Expand URL template with property values
fn expand_url_template(
    template: &str,
    properties: &HashMap<String, PropertyValue>,
    version: &str,
) -> Result<Vec<PackageUrl>> {
    let mut urls = Vec::new();

    let template_regex =
        regex::Regex::new(r#"\#\{([^}]+)\}"#).context("compiling template regex")?;

    // Check if template contains arch variable
    let has_arch = template.contains("#{arch}");

    if has_arch {
        // Generate one URL per arch variant
        if let Some(PropertyValue::Dict(arch_dict)) = properties.get("arch") {
            for (arch_key, arch_value) in arch_dict {
                let mut expanded = template.to_string();

                for caps in template_regex.captures_iter(template) {
                    let var_expr = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let replacement = evaluate_template_expression(
                        var_expr,
                        properties,
                        version,
                        Some(arch_value),
                    )?;

                    expanded = expanded.replace(&format!("#{{{}}}", var_expr), &replacement);
                }

                urls.push(PackageUrl {
                    url: url_unescape(&expanded),
                    version: version.to_string(),
                    arch: arch_key.to_string(),
                });
            }
        } else {
            bail!("URL template contains #{{arch}} but no arch property found");
        }
    } else {
        // Single URL, no arch iteration
        let mut expanded = template.to_string();

        for caps in template_regex.captures_iter(template) {
            let var_expr = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let replacement = evaluate_template_expression(var_expr, properties, version, None)?;

            expanded = expanded.replace(&format!("#{{{}}}", var_expr), &replacement);
        }

        urls.push(PackageUrl {
            url: url_unescape(&expanded),
            version: version.to_string(),
            arch: "x64".to_string(),
        });
    }

    Ok(urls)
}

/// Evaluate a template expression like "version", "version.csv.first", "arch"
fn evaluate_template_expression(
    expr: &str,
    properties: &HashMap<String, PropertyValue>,
    version: &str,
    arch_value: Option<&str>,
) -> Result<String> {
    // Handle special case: arch (when we're iterating)
    if expr == "arch"
        && let Some(arch) = arch_value
    {
        return Ok(arch.to_string());
    }

    // Parse expression: variable or variable.method1.method2
    let parts: Vec<&str> = expr.split('.').collect();
    let var_name = parts[0];

    // Get the property value
    let value = if var_name == "version" {
        PropertyValue::String(version.to_string())
    } else if let Some(prop) = properties.get(var_name) {
        prop.clone()
    } else {
        bail!("unknown template variable: {}", var_name);
    };

    // Apply methods if any
    if parts.len() > 1 {
        value
            .apply_method(&parts[1..])
            .ok_or_else(|| anyhow::anyhow!("cannot apply method {} to {}", parts[1], var_name))
    } else {
        match value {
            PropertyValue::String(s) => Ok(s),
            PropertyValue::Dict(_) => {
                bail!("cannot use dict property {} without key", var_name)
            }
        }
    }
}

/// Extract version from URL using regex pattern
fn extract_version(input: &str, pattern: &str) -> Option<String> {
    let re = regex::Regex::new(pattern).ok()?;
    let caps = re.captures(input)?;
    caps.get(1).map(|m| m.as_str().to_string())
}

/// Determine the filename to use for the destination file
fn determine_filename(
    custom_filename: Option<&str>,
    url: &str,
    package_name: &str,
    version: &str,
) -> String {
    if let Some(filename) = custom_filename {
        filename.to_string()
    } else {
        filename_from_url(url).unwrap_or_else(|| format!("{}-{}.bin", package_name, version))
    }
}

fn filename_from_url(url: &str) -> Option<String> {
    // First, strip off query parameters
    let main = url.split('?').next().unwrap_or(url);

    // Handle Scoop-style fragments like #/dl.7z or #/installer.exe
    let without_fragment = main.split('#').next().unwrap_or(main);

    // Extract the last path segment
    let seg = without_fragment
        .rsplit('/')
        .next()
        .unwrap_or(without_fragment)
        .trim();

    if seg.is_empty() {
        None
    } else {
        Some(seg.to_string())
    }
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
    fn test_parse_homebrew_telegram_manifest() {
        let content = r#"
cask "telegram" do
  version "12.2.1,277150"
  sha256 "d5659b0f8b3815988b1601707599cbafb9e3bfd49c25b9907e3269c0c5183a73"

  url "https://osx.telegram.org/updates/Telegram-#{version.csv.first}.#{version.csv.second}.app.zip"
  name "Telegram for macOS"
end
"#;
        let result = parse_homebrew_manifest(content, None).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].version, "12.2.1,277150");
        assert_eq!(
            result[0].url,
            "https://osx.telegram.org/updates/Telegram-12.2.1.277150.app.zip"
        );
    }

    #[test]
    fn test_filename_from_url() {
        assert_eq!(
            filename_from_url("https://example.com/path/file.zip"),
            Some("file.zip".to_string())
        );
        assert_eq!(
            filename_from_url("https://example.com/path/file.zip?param=value"),
            Some("file.zip".to_string())
        );
        assert_eq!(filename_from_url("https://example.com/"), None);
        assert_eq!(
            filename_from_url("https://example.com/installer.exe#/install.exe"),
            Some("installer.exe".to_string())
        );
    }

    #[test]
    fn test_language_priority() {
        assert_eq!(get_language_priority("zh-CN"), 4);
        assert_eq!(get_language_priority("zh"), 3);
        assert_eq!(get_language_priority("en-US"), 2);
        assert_eq!(get_language_priority("en"), 1);
        assert_eq!(get_language_priority("fr"), 0);
    }
}
