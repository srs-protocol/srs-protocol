//! OraSRS v2.0 Lightweight Threat Detection Agent
//! 
//! This crate provides a lightweight agent for detecting and reporting threats
//! as part of the OraSRS v2.0 coordinated defense framework.

pub mod agent;
pub mod config;
pub mod monitor;
pub mod analyzer;
pub mod reporter;
pub mod crypto;
pub mod p2p;
pub mod threat_intel;
pub mod threat_intel_upstream;
pub mod consensus_verification;
pub mod credibility_enhancement;
pub mod compliance;
pub mod error;
pub mod blocklist_exporter;

pub use agent::OrasrsAgent;
pub use config::AgentConfig;
pub use threat_intel_upstream::ThreatIntelAggregator;
pub use consensus_verification::ConsensusEngine;
pub use credibility_enhancement::CredibilityEngine;
pub use error::{AgentError, Result};
pub use blocklist_exporter::{BlocklistExporter, start_blocklist_exporter};

/// Threat level enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThreatLevel {
    Info = 0,
    Warning = 1,
    Critical = 2,
    Emergency = 3,
}

/// Threat type enumeration
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThreatType {
    DDoS,
    Malware,
    Phishing,
    BruteForce,
    SuspiciousConnection,
    AnomalousBehavior,
    IoCMatch,
}

/// Threat evidence structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatEvidence {
    pub id: String,
    pub timestamp: i64,
    pub source_ip: String,
    pub target_ip: String,
    pub threat_type: ThreatType,
    pub threat_level: ThreatLevel,
    pub context: String,
    pub evidence_hash: String,
    pub geolocation: String,
    pub network_flow: String,
    pub agent_id: String,
    pub reputation: f64,
    pub compliance_tag: String,
    pub region: String,
}

/// Agent status structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentStatus {
    pub agent_id: String,
    pub version: String,
    pub uptime: u64,
    pub threat_count: u64,
    pub reputation: f64,
    pub memory_usage: usize,
    pub cpu_usage: f64,
    pub network_usage: u64,
    pub last_threat_report: Option<i64>,
    pub p2p_connected: bool,
    pub compliance_mode: String,
}