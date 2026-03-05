// VEIL — Server Configuration
// Spec reference: Sections 2.3, 5.3

use serde::Deserialize;
use std::path::PathBuf;

/// Configuration for the Veil Relay Service.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Server listen address (e.g., "0.0.0.0:8443").
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Path to TLS certificate chain (PEM).
    pub tls_cert_path: PathBuf,

    /// Path to TLS private key (PEM).
    pub tls_key_path: PathBuf,

    /// Path to sled database directory.
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,

    /// Maximum messages queued per device before rejecting new ones.
    #[serde(default = "default_max_queue_size")]
    pub max_queue_size: usize,

    /// Number of anonymous credential tokens issued per registration.
    #[serde(default = "default_initial_token_count")]
    pub initial_token_count: usize,

    /// Number of fresh tokens included with message retrieval
    /// when client balance is estimated to be low.
    #[serde(default = "default_replenish_token_count")]
    pub replenish_token_count: usize,

    /// APNs configuration (optional — push disabled if absent).
    pub apns: Option<ApnsConfig>,
}

/// Apple Push Notification Service configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct ApnsConfig {
    /// Path to APNs authentication key (.p8 file).
    pub key_path: PathBuf,

    /// APNs Key ID.
    pub key_id: String,

    /// Apple Team ID.
    pub team_id: String,

    /// APNs bundle ID (e.g., "com.veil.app").
    pub bundle_id: String,

    /// Use production APNs endpoint (vs sandbox).
    #[serde(default)]
    pub production: bool,
}

// ── Defaults ──

fn default_listen_addr() -> String {
    "0.0.0.0:8443".to_string()
}

fn default_db_path() -> PathBuf {
    PathBuf::from("./veil-relay-data")
}

fn default_max_queue_size() -> usize {
    10_000
}

fn default_initial_token_count() -> usize {
    100
}

fn default_replenish_token_count() -> usize {
    20
}

impl Config {
    /// Load configuration from a JSON file.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Load configuration from environment variables with fallback to file.
    pub fn load() -> anyhow::Result<Self> {
        if let Ok(path) = std::env::var("VEIL_CONFIG") {
            Self::from_file(&path)
        } else {
            Self::from_file("config.json")
        }
    }
}
