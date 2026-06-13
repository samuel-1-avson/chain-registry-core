// crates/cli/src/config_file.rs
// Configuration file management for creg CLI.
//
// Config file location:
//   - Unix: ~/.creg/config.toml
//   - Windows: %USERPROFILE%\.creg\config.toml
//
// Environment variables override config file values.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Node connection settings
    #[serde(default)]
    pub node: NodeConfig,

    /// Default values for commands
    #[serde(default)]
    pub defaults: DefaultConfig,

    /// Display preferences
    #[serde(default)]
    pub display: DisplayConfig,

    /// IPFS configuration
    #[serde(default)]
    pub ipfs: IpfsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Default node URL to connect to
    #[serde(default = "default_node_url")]
    pub url: String,

    /// Timeout for API requests (seconds)
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            url: default_node_url(),
            timeout: default_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DefaultConfig {
    /// Default ecosystem (npm, pip, cargo, etc.)
    pub ecosystem: Option<String>,

    /// Allow unverified packages by default
    #[serde(default)]
    pub allow_unverified: bool,

    /// Default stake amount for publishers
    pub stake_amount: Option<String>,

    /// Path to publisher key file
    pub publisher_key: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayConfig {
    /// Enable colored output
    #[serde(default = "default_true")]
    pub colors: bool,

    /// Output format (text, json)
    #[serde(default = "default_format")]
    pub format: OutputFormat,

    /// Show progress bars
    #[serde(default = "default_true")]
    pub progress: bool,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            colors: true,
            format: OutputFormat::Text,
            progress: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsConfig {
    /// IPFS daemon URL
    #[serde(default = "default_ipfs_url")]
    pub url: String,

    /// Timeout for IPFS operations (seconds)
    #[serde(default = "default_ipfs_timeout")]
    pub timeout: u64,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            url: default_ipfs_url(),
            timeout: default_ipfs_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

fn default_node_url() -> String {
    // Local node by default; override with --node-url, CREG_NODE_URL, or a public
    // testnet endpoint in the config file. (No live public default is shipped yet.)
    "http://localhost:8080".to_string()
}

fn default_timeout() -> u64 {
    30
}

fn default_ipfs_url() -> String {
    "http://127.0.0.1:5001".to_string()
}

fn default_ipfs_timeout() -> u64 {
    120
}

fn default_true() -> bool {
    true
}

fn default_format() -> OutputFormat {
    OutputFormat::Text
}

impl Config {
    /// Load configuration from file, with environment variable overrides
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        let mut config = if config_path.exists() {
            let content = std::fs::read_to_string(&config_path).with_context(|| {
                format!("Failed to read config file: {}", config_path.display())
            })?;
            toml::from_str(&content).with_context(|| {
                format!("Failed to parse config file: {}", config_path.display())
            })?
        } else {
            Config::default()
        };

        // Apply environment variable overrides
        config.apply_env_overrides();

        Ok(config)
    }

    /// Create a default configuration file if it doesn't exist
    pub fn init() -> Result<PathBuf> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            println!("Config file already exists at: {}", config_path.display());
            return Ok(config_path);
        }

        // Ensure directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let default_config = Config::default();
        let content = toml::to_string_pretty(&default_config)?;
        std::fs::write(&config_path, content)?;

        println!("Created default config file at: {}", config_path.display());
        Ok(config_path)
    }

    /// Get the path to the config file
    pub fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        Ok(home.join(".creg").join("config.toml"))
    }

    /// Apply environment variable overrides
    fn apply_env_overrides(&mut self) {
        if let Ok(url) = std::env::var("CREG_NODE_URL") {
            self.node.url = url;
        }
        if let Ok(url) = std::env::var("CREG_IPFS_URL") {
            self.ipfs.url = url;
        }
        if let Ok(key) = std::env::var("CREG_PUBLISHER_KEY") {
            self.defaults.publisher_key = Some(PathBuf::from(key));
        }
        if std::env::var("NO_COLOR").is_ok() {
            self.display.colors = false;
        }
    }

    /// Get the effective node URL (CLI arg > env var > config file > default)
    #[allow(dead_code)]
    pub fn node_url(&self, cli_override: Option<&str>) -> String {
        cli_override
            .map(String::from)
            .or_else(|| std::env::var("CREG_NODE_URL").ok())
            .unwrap_or_else(|| self.node.url.clone())
    }

    /// Get the effective IPFS URL
    #[allow(dead_code)]
    pub fn ipfs_url(&self) -> String {
        std::env::var("CREG_IPFS_URL")
            .ok()
            .unwrap_or_else(|| self.ipfs.url.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.node.url, "http://localhost:8080");
        assert_eq!(config.node.timeout, 30);
        assert!(config.display.colors);
        assert!(config.display.progress);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("url"));
        assert!(toml_str.contains("timeout"));
    }
}
