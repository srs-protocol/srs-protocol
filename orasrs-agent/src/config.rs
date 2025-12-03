use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::{ThreatLevel};

/// Agent configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Unique agent identifier
    pub agent_id: String,
    
    /// Deployment region (auto-detected or specified)
    pub region: String,
    
    /// Privacy level (1-4)
    pub privacy_level: u8,
    
    /// Compliance mode (gdpr, ccpa, china, global)
    pub compliance_mode: String,
    
    /// Maximum memory usage in bytes (default: 5MB)
    pub max_memory: usize,
    
    /// CPU usage limit as percentage (default: 5)
    pub cpu_limit: f64,
    
    /// Network usage limit in bytes/sec (default: 10KB)
    pub network_limit: usize,
    
    /// Enabled monitoring modules
    pub enabled_modules: ModuleConfig,
    
    /// P2P network configuration
    pub p2p_config: P2pConfig,
    
    /// Cryptographic configuration
    pub crypto_config: CryptoConfig,
    
    /// Local storage configuration
    pub storage_config: StorageConfig,
    
    /// Reputation threshold
    pub reputation_threshold: f64,
    
    /// Update interval in seconds
    pub update_interval: u64,
    
    /// Whether blocklist export is enabled
    pub blocklist_export_enabled: bool,
    
    /// Blocklist file path
    pub blocklist_file: Option<String>,
    
    /// Minimum threat level for blocklist export
    pub blocklist_min_threat_level: Option<ThreatLevel>,
    
    /// Blocklist export interval in seconds
    pub blocklist_export_interval: Option<u64>,
}

/// Monitoring modules configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub netflow: bool,
    pub syscall: bool,
    pub tls_inspect: bool,
    pub geo_fence: bool,
}

/// P2P network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    pub bootstrap_nodes: Vec<String>,
    pub listen_port: u16,
    pub max_connections: usize,
    pub reconnect_interval: u64,
}

/// Cryptographic configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub use_sm_crypto: bool,
    pub sm2_private_key: Option<String>,
    pub sm2_public_key: Option<String>,
    pub encryption_algorithm: String,  // "sm4" or "aes256"
}

/// Local storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    pub max_log_size: usize,
    pub retention_days: u32,
    pub encryption_enabled: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: uuid::Uuid::new_v4().to_string(),
            region: "auto".to_string(),
            privacy_level: 2,  // Default to GDPR level
            compliance_mode: "global".to_string(),
            max_memory: 5 * 1024 * 1024, // 5MB
            cpu_limit: 5.0,
            network_limit: 10 * 1024, // 10KB
            enabled_modules: ModuleConfig::default(),
            p2p_config: P2pConfig::default(),
            crypto_config: CryptoConfig::default(),
            storage_config: StorageConfig::default(),
            reputation_threshold: 0.6,
            update_interval: 30, // 30 seconds
            blocklist_export_enabled: false,
            blocklist_file: Some("./blocklist.txt".to_string()),
            blocklist_min_threat_level: Some(crate::ThreatLevel::Warning),
            blocklist_export_interval: Some(300), // 5 minutes
        }
    }
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            netflow: true,
            syscall: true,
            tls_inspect: true,
            geo_fence: true,
        }
    }
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: vec![
                "/ip4/159.138.224.180/tcp/4001/p2p/12D3KooWCeV2JWivXqakX9ZR53z32k7Z4FwKjZ7y6zY6o2Rr5v5o".to_string(),
                "/ip4/159.138.224.181/tcp/4001/p2p/12D3KooWCeV2JWivXqakX9ZR53z32k7Z4FwKjZ7y6zY6o2Rr5v5p".to_string(),
            ],
            listen_port: 4001,
            max_connections: 50,
            reconnect_interval: 30,
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            use_sm_crypto: false,
            sm2_private_key: None,
            sm2_public_key: None,
            encryption_algorithm: "aes256".to_string(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            max_log_size: 10 * 1024 * 1024, // 10MB
            retention_days: 30,
            encryption_enabled: true,
        }
    }
}