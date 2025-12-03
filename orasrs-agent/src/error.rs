use thiserror::Error;

/// Result type for OraSRS Agent operations
pub type Result<T> = std::result::Result<T, AgentError>;

/// Error types for OraSRS Agent
#[derive(Error, Debug)]
pub enum AgentError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),
    
    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    /// P2P network error
    #[error("P2P network error: {0}")]
    P2pError(String),
    
    /// Threat detection error
    #[error("Threat detection error: {0}")]
    ThreatDetectionError(String),
    
    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    /// System error
    #[error("System error: {0}")]
    SystemError(String),
    
    /// Compliance error
    #[error("Compliance error: {0}")]
    ComplianceError(String),
    
    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}