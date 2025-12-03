//! OraSRS Blocklist Export Demo
//! 
//! This demonstrates how the OraSRS Agent threat detection
//! gets converted to blocklist.txt format for use with existing firewalls/WAFs.

use std::fs::File;
use std::io::Write;
use std::collections::HashSet;

/// Threat level enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    Info = 0,
    Warning = 1,
    Critical = 2,
    Emergency = 3,
}

/// Threat type enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone)]
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

/// Blocklist exporter to convert threat evidence to blocklist.txt format
pub struct BlocklistExporter {
    blocklist_file: String,
    threat_cache: HashSet<String>,  // Cache to avoid duplicate IPs
    min_threat_level: ThreatLevel,  // Minimum threat level to include in blocklist
}

impl BlocklistExporter {
    /// Create a new blocklist exporter
    pub fn new(blocklist_file: String, min_threat_level: ThreatLevel) -> Self {
        Self {
            blocklist_file,
            threat_cache: HashSet::new(),
            min_threat_level,
        }
    }

    /// Add an IP to the blocklist file
    pub fn add_to_blocklist(&mut self, ip: &str, evidence: &ThreatEvidence) -> Result<(), Box<dyn std::error::Error>> {
        // Check if threat level is high enough for blocklist
        if evidence.threat_level as u8 >= self.min_threat_level as u8 {
            // Add source IP to blocklist if not already present
            if self.threat_cache.insert(ip.to_string()) {
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.blocklist_file)?;
                
                // Write the IP with comment about the threat
                writeln!(
                    file, 
                    "{} # {} - {} - {} - Agent: {}", 
                    ip,
                    self.threat_level_to_string(evidence.threat_level),
                    self.threat_type_to_string(&evidence.threat_type),
                    evidence.context,
                    evidence.agent_id
                )?;
                
                println!("Added {} to blocklist: {} - {}", ip, self.threat_type_to_string(&evidence.threat_type), evidence.context);
            }
        }
        
        Ok(())
    }

    /// Convert threat level to string
    fn threat_level_to_string(&self, level: ThreatLevel) -> &'static str {
        match level {
            ThreatLevel::Info => "INFO",
            ThreatLevel::Warning => "WARNING",
            ThreatLevel::Critical => "CRITICAL",
            ThreatLevel::Emergency => "EMERGENCY",
        }
    }

    /// Convert threat type to string
    fn threat_type_to_string(&self, threat_type: &ThreatType) -> &'static str {
        match threat_type {
            ThreatType::DDoS => "ddos",
            ThreatType::Malware => "malware",
            ThreatType::Phishing => "phishing",
            ThreatType::BruteForce => "brute_force",
            ThreatType::SuspiciousConnection => "suspicious_connection",
            ThreatType::AnomalousBehavior => "anomalous_behavior",
            ThreatType::IoCMatch => "ioc_match",
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("OraSRS Blocklist Export Demo");
    println!("============================");
    
    // Initialize blocklist file with header
    let mut file = File::create("blocklist.txt")?;
    writeln!(file, "# OraSRS Agent Blocklist")?;
    writeln!(file, "# Generated: {}", chrono::Utc::now().to_rfc3339())?;
    writeln!(file, "# Contains IP addresses detected as threats by OraSRS Agent")?;
    writeln!(file, "# Minimum threat level: WARNING")?;
    writeln!(file, "")?;
    
    // Create blocklist exporter
    let mut exporter = BlocklistExporter::new("blocklist.txt".to_string(), ThreatLevel::Warning);
    
    // Simulate threat evidences detected by OraSRS Agent
    let threat_evidences = vec![
        ThreatEvidence {
            id: "threat_001".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            source_ip: "192.168.1.100".to_string(),
            target_ip: "10.0.0.5".to_string(),
            threat_type: ThreatType::DDoS,
            threat_level: ThreatLevel::Critical,
            context: "SYN flood attack detected".to_string(),
            evidence_hash: "a1b2c3d4e5f6...".to_string(),
            geolocation: "Shanghai, China".to_string(),
            network_flow: "source_port: 1024-65535, dest_port: 80".to_string(),
            agent_id: "edge_agent_001".to_string(),
            reputation: 0.95,
            compliance_tag: "global".to_string(),
            region: "CN".to_string(),
        },
        ThreatEvidence {
            id: "threat_002".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            source_ip: "203.0.113.45".to_string(),
            target_ip: "10.0.0.10".to_string(),
            threat_type: ThreatType::Malware,
            threat_level: ThreatLevel::Critical,
            context: "Malware distribution attempt".to_string(),
            evidence_hash: "f6e5d4c3b2a1...".to_string(),
            geolocation: "Moscow, Russia".to_string(),
            network_flow: "source_port: 443, dest_port: 8080".to_string(),
            agent_id: "edge_agent_002".to_string(),
            reputation: 0.87,
            compliance_tag: "global".to_string(),
            region: "RU".to_string(),
        },
        ThreatEvidence {
            id: "threat_003".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            source_ip: "198.51.100.23".to_string(),
            target_ip: "10.0.1.1".to_string(),
            threat_type: ThreatType::BruteForce,
            threat_level: ThreatLevel::Warning,
            context: "Multiple failed login attempts".to_string(),
            evidence_hash: "x7y8z9a0b1c2...".to_string(),
            geolocation: "Frankfurt, Germany".to_string(),
            network_flow: "source_port: 22, dest_port: 22".to_string(),
            agent_id: "edge_agent_003".to_string(),
            reputation: 0.92,
            compliance_tag: "global".to_string(),
            region: "DE".to_string(),
        },
    ];
    
    // Add each threat to the blocklist
    for evidence in threat_evidences {
        exporter.add_to_blocklist(&evidence.source_ip, &evidence)?;
    }
    
    println!("\nBlocklist export completed!");
    println!("Check 'blocklist.txt' file for the generated blocklist.");
    println!("\nThis blocklist can be used with existing firewalls/WAFs.");
    println!("URL: file://$(pwd)/blocklist.txt");
    
    Ok(())
}
