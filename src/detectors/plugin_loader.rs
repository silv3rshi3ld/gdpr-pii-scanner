/// Plugin loader for loading custom detectors from TOML files
///
/// Scans a directory for `.detector.toml` files and loads them as plugin detectors.
use crate::detectors::plugin::{PluginConfig, PluginDetector};
use std::fs;
use std::path::{Path, PathBuf};

/// Load all plugin detectors from a directory
///
/// # Arguments
/// * `plugin_dir` - Directory to scan for `.detector.toml` files
///
/// # Returns
/// * `Ok(Vec<PluginDetector>)` - List of successfully loaded plugins
/// * `Err(String)` - Error message if directory cannot be read
///
/// # Example
/// ```no_run
/// use pii_radar::detectors::plugin_loader::load_plugins_from_directory;
///
/// let plugins = load_plugins_from_directory("./plugins").unwrap();
/// println!("Loaded {} custom detectors", plugins.len());
/// ```
pub fn load_plugins_from_directory<P: AsRef<Path>>(
    plugin_dir: P,
) -> Result<Vec<PluginDetector>, String> {
    let path = plugin_dir.as_ref();

    if !path.exists() {
        return Err(format!(
            "Plugin directory does not exist: {}",
            path.display()
        ));
    }

    if !path.is_dir() {
        return Err(format!(
            "Plugin path is not a directory: {}",
            path.display()
        ));
    }

    let mut plugins = Vec::new();
    let mut errors = Vec::new();

    // Read directory entries
    let entries =
        fs::read_dir(path).map_err(|e| format!("Failed to read plugin directory: {}", e))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                errors.push(format!("Failed to read directory entry: {}", e));
                continue;
            }
        };

        let file_path = entry.path();

        // Skip non-files
        if !file_path.is_file() {
            continue;
        }

        // Only process .detector.toml files
        if let Some(file_name) = file_path.file_name() {
            let file_name_str = file_name.to_string_lossy();
            if !file_name_str.ends_with(".detector.toml") {
                continue;
            }

            // Attempt to load plugin
            match load_plugin_from_file(&file_path) {
                Ok(plugin) => {
                    println!(
                        "✓ Loaded plugin: {} ({})",
                        plugin.config().name,
                        file_name_str
                    );
                    plugins.push(plugin);
                }
                Err(e) => {
                    let error_msg = format!("Failed to load {}: {}", file_name_str, e);
                    eprintln!("✗ {}", error_msg);
                    errors.push(error_msg);
                }
            }
        }
    }

    // Report summary
    if !errors.is_empty() {
        eprintln!("\n⚠ Warning: {} plugin(s) failed to load", errors.len());
    }

    if plugins.is_empty() && errors.is_empty() {
        return Err(format!(
            "No plugin files found in directory: {} (looking for *.detector.toml)",
            path.display()
        ));
    }

    Ok(plugins)
}

/// Load a single plugin from a TOML file
///
/// # Arguments
/// * `file_path` - Path to the `.detector.toml` file
///
/// # Returns
/// * `Ok(PluginDetector)` - Successfully loaded plugin
/// * `Err(String)` - Error message if file cannot be loaded or parsed
pub fn load_plugin_from_file<P: AsRef<Path>>(file_path: P) -> Result<PluginDetector, String> {
    let path = file_path.as_ref();

    // Read file contents
    let contents = fs::read_to_string(path).map_err(|e| format!("Failed to read file: {}", e))?;

    // Parse TOML
    let config: PluginConfig =
        toml::from_str(&contents).map_err(|e| format!("Failed to parse TOML: {}", e))?;

    // Create detector from config
    PluginDetector::new(config)
}

/// Discover plugin files in a directory
///
/// Returns paths to all `.detector.toml` files found.
pub fn discover_plugin_files<P: AsRef<Path>>(plugin_dir: P) -> Result<Vec<PathBuf>, String> {
    let path = plugin_dir.as_ref();

    if !path.exists() {
        return Err(format!(
            "Plugin directory does not exist: {}",
            path.display()
        ));
    }

    let entries =
        fs::read_dir(path).map_err(|e| format!("Failed to read plugin directory: {}", e))?;

    let mut plugin_files = Vec::new();

    for entry in entries.flatten() {
        let file_path = entry.path();
        if file_path.is_file() {
            if let Some(file_name) = file_path.file_name() {
                let file_name_str = file_name.to_string_lossy();
                if file_name_str.ends_with(".detector.toml") {
                    plugin_files.push(file_path);
                }
            }
        }
    }

    Ok(plugin_files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::detector::Detector;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_plugin_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let file_path = dir.join(format!("{}.detector.toml", name));
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file_path
    }

    #[test]
    fn test_load_valid_plugin() {
        let temp_dir = TempDir::new().unwrap();

        let config = r#"
id = "test_id"
name = "Test Detector"
country = "universal"
category = "custom"
description = "A test detector"

[[patterns]]
pattern = "TEST-\\d{4}"
confidence = "high"

[validation]
min_length = 9
max_length = 9
        "#;

        let file_path = create_test_plugin_file(temp_dir.path(), "test", config);

        let result = load_plugin_from_file(&file_path);
        assert!(result.is_ok());

        let plugin = result.unwrap();
        assert_eq!(plugin.id(), "test_id");
        assert_eq!(plugin.name(), "Test Detector");
    }

    #[test]
    fn test_load_invalid_toml() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_plugin_file(temp_dir.path(), "invalid", "{ invalid toml");

        let result = load_plugin_from_file(&file_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse TOML"));
    }

    #[test]
    fn test_load_plugins_from_directory() {
        let temp_dir = TempDir::new().unwrap();

        // Create multiple plugin files
        let config1 = r#"
id = "plugin1"
name = "Plugin 1"
country = "nl"
category = "custom"
description = "First plugin"

[[patterns]]
pattern = "P1-\\d{4}"
confidence = "medium"
        "#;

        let config2 = r#"
id = "plugin2"
name = "Plugin 2"
country = "gb"
category = "custom"
description = "Second plugin"

[[patterns]]
pattern = "P2-\\d{4}"
confidence = "high"
        "#;

        create_test_plugin_file(temp_dir.path(), "plugin1", config1);
        create_test_plugin_file(temp_dir.path(), "plugin2", config2);

        // Create a non-plugin file (should be ignored)
        let non_plugin_path = temp_dir.path().join("readme.txt");
        fs::write(non_plugin_path, "This is not a plugin").unwrap();

        let result = load_plugins_from_directory(temp_dir.path());
        assert!(result.is_ok());

        let plugins = result.unwrap();
        assert_eq!(plugins.len(), 2);

        // Check both plugins loaded
        let ids: Vec<&str> = plugins.iter().map(|p| p.id()).collect();
        assert!(ids.contains(&"plugin1"));
        assert!(ids.contains(&"plugin2"));
    }

    #[test]
    fn test_nonexistent_directory() {
        let result = load_plugins_from_directory("/nonexistent/path/to/plugins");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[test]
    fn test_discover_plugin_files() {
        let temp_dir = TempDir::new().unwrap();

        create_test_plugin_file(temp_dir.path(), "detector1", "content");
        create_test_plugin_file(temp_dir.path(), "detector2", "content");

        // Create non-plugin file
        fs::write(temp_dir.path().join("other.txt"), "content").unwrap();

        let result = discover_plugin_files(temp_dir.path());
        assert!(result.is_ok());

        let files = result.unwrap();
        assert_eq!(files.len(), 2);

        for file in &files {
            assert!(file.to_string_lossy().ends_with(".detector.toml"));
        }
    }

    #[test]
    fn test_empty_directory() {
        let temp_dir = TempDir::new().unwrap();

        let result = load_plugins_from_directory(temp_dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No plugin files found"));
    }
}
