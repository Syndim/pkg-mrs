//! Version extraction utilities.

/// Extract version from string using regex pattern (first capture group).
pub fn extract_version(input: &str, pattern: &str) -> Option<String> {
    let re = regex::Regex::new(pattern).ok()?;
    re.captures(input)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

/// Extract filename from URL.
/// Strips query parameters and fragments, returns the last path segment.
pub fn filename_from_url(url: &str) -> Option<String> {
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

/// Determine the filename to use for the destination file.
/// Uses custom filename if provided, otherwise extracts from URL or falls back to default.
pub fn determine_filename(
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
        assert_eq!(
            extract_version("release-2.0.0", r"release-([0-9.]+)"),
            Some("2.0.0".to_string())
        );
    }

    #[test]
    fn test_filename_from_url() {
        assert_eq!(
            filename_from_url("https://example.com/path/file.zip"),
            Some("file.zip".to_string())
        );
        assert_eq!(
            filename_from_url("https://example.com/path/file.zip?token=abc"),
            Some("file.zip".to_string())
        );
        assert_eq!(
            filename_from_url("https://example.com/path/file.exe#/dl.7z"),
            Some("file.exe".to_string())
        );
        assert_eq!(filename_from_url("https://example.com/"), None);
    }

    #[test]
    fn test_determine_filename() {
        // Custom filename takes priority
        assert_eq!(
            determine_filename(Some("custom.zip"), "https://example.com/file.tar.gz", "pkg", "1.0"),
            "custom.zip"
        );

        // Extract from URL
        assert_eq!(
            determine_filename(None, "https://example.com/file.tar.gz", "pkg", "1.0"),
            "file.tar.gz"
        );

        // Fallback when URL has no filename
        assert_eq!(
            determine_filename(None, "https://example.com/", "pkg", "1.0"),
            "pkg-1.0.bin"
        );
    }
}
