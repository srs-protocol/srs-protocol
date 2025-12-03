use crate::{ThreatEvidence, AgentConfig, crypto::CryptoProvider, error::{AgentError, Result}};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Threat evidence collector and reporter
pub struct EvidenceCollector {
    agent_id: String,
    config: AgentConfig,
    evidence_queue: tokio::sync::mpsc::UnboundedReceiver<ThreatEvidence>,
    blocklist_sender: Option<tokio::sync::mpsc::UnboundedSender<ThreatEvidence>>,
    reputation: f64,
}

impl EvidenceCollector {
    pub fn new(
        agent_id: String,
        config: AgentConfig,
        evidence_queue: tokio::sync::mpsc::UnboundedReceiver<ThreatEvidence>,
        blocklist_sender: Option<tokio::sync::mpsc::UnboundedSender<ThreatEvidence>>,
    ) -> Self {
        Self {
            agent_id,
            config,
            evidence_queue,
            blocklist_sender,
            reputation: 1.0, // Start with good reputation
        }
    }

    /// Start collecting and processing evidence
    pub async fn start_collection(&mut self) -> Result<()> {
        log::info!("Starting evidence collection...");
        
        while let Some(mut evidence) = self.evidence_queue.recv().await {
            // Set agent-specific fields
            evidence.agent_id = self.agent_id.clone();
            evidence.reputation = self.reputation;
            evidence.compliance_tag = self.config.compliance_mode.clone();
            evidence.region = self.config.region.clone();
            
            // Process the evidence based on privacy and compliance settings
            let processed_evidence = self.process_evidence(evidence.clone())?; // Clone for blocklist
            
            // Send to blocklist exporter if enabled
            if let Some(ref sender) = self.blocklist_sender {
                // Only send to blocklist if threat level is high enough
                if processed_evidence.threat_level as u8 >= self.config.blocklist_min_threat_level.unwrap_or(crate::ThreatLevel::Warning) as u8 {
                    let _ = sender.send(processed_evidence.clone());
                }
            }
            
            // Submit evidence to the threat intelligence fabric
            if let Err(e) = self.submit_evidence(&processed_evidence).await {
                log::error!("Failed to submit evidence: {}", e);
                // Update reputation based on failure
                self.update_reputation(false);
            } else {
                log::debug!("Evidence submitted successfully");
                // Update reputation based on success
                self.update_reputation(true);
            }
        }
        
        Ok(())
    }

    /// Process evidence according to privacy and compliance settings
    fn process_evidence(&self, mut evidence: ThreatEvidence) -> Result<ThreatEvidence> {
        // Apply privacy settings based on privacy level
        match self.config.privacy_level {
            1 => { // GDPR: anonymize to /24
                evidence.source_ip = self.anonymize_ip(&evidence.source_ip, 24);
                evidence.target_ip = self.anonymize_ip(&evidence.target_ip, 24);
            },
            2 => { // CCPA: anonymize to /16
                evidence.source_ip = self.anonymize_ip(&evidence.source_ip, 16);
                evidence.target_ip = self.anonymize_ip(&evidence.target_ip, 16);
            },
            3 => { // China: full IP allowed
                // No anonymization needed
            },
            _ => { // Global: anonymize to /16
                evidence.source_ip = self.anonymize_ip(&evidence.source_ip, 16);
                evidence.target_ip = self.anonymize_ip(&evidence.target_ip, 16);
            }
        }

        // Encrypt sensitive fields if required
        if self.config.storage_config.encryption_enabled {
            evidence.context = CryptoProvider::encrypt_data(evidence.context.as_bytes(), &[0u8; 32])
                .map(|v| format!("{:?}", v))  // Simplified representation
                .unwrap_or(evidence.context);
        }

        // Update evidence hash after processing
        let evidence_str = format!("{}/{}/{}/{}", 
            evidence.source_ip, 
            evidence.target_ip, 
            evidence.threat_type.as_ref(), 
            evidence.context);
        evidence.evidence_hash = CryptoProvider::blake3_hash(evidence_str.as_bytes());

        Ok(evidence)
    }

    /// Anonymize IP address to specified subnet size
    fn anonymize_ip(&self, ip: &str, subnet_bits: u8) -> String {
        // This is a simplified IP anonymization
        // In a real implementation, we'd use proper IP address manipulation
        if subnet_bits >= 32 {
            return ip.to_string(); // No anonymization
        }

        // For IPv4, anonymize the last octet(s) based on subnet_bits
        if ip.contains('.') {
            let octets: Vec<&str> = ip.split('.').collect();
            if octets.len() == 4 {
                let keep_octets = match subnet_bits {
                    0..=8 => 1,
                    9..=16 => 2,
                    17..=24 => 3,
                    _ => 4, // Don't anonymize if >= 24
                };
                
                if keep_octets >= 4 {
                    return ip.to_string(); // No anonymization needed
                }
                
                let mut result = String::new();
                for i in 0..4 {
                    if i < keep_octets {
                        result.push_str(octets[i]);
                    } else {
                        result.push_str("0");
                    }
                    
                    if i < 3 {
                        result.push('.');
                    }
                }
                return result;
            }
        }

        // For IPv6 or malformed IPs, return a placeholder
        "0.0.0.0".to_string()
    }

    /// Submit evidence to the threat intelligence fabric
    async fn submit_evidence(&self, evidence: &ThreatEvidence) -> Result<()> {
        // In a real implementation, this would submit to the P2P network
        // or to the multi-chain consensus layer
        log::info!("Submitting threat evidence: {} - {}", evidence.threat_type.as_ref(), evidence.threat_level as u8);
        
        // For now, just log the evidence (in real implementation, send to P2P network)
        println!("Would submit evidence to P2P network: {:?}", evidence);
        
        Ok(())
    }

    /// Update agent reputation based on submission success/failure
    fn update_reputation(&mut self, success: bool) {
        if success {
            // Small reputation increase for successful submission
            self.reputation = (self.reputation + 0.01).min(1.0);
        } else {
            // Larger reputation decrease for failed submission
            self.reputation = (self.reputation - 0.05).max(0.0);
        }
    }

    /// Get current reputation
    pub fn get_reputation(&self) -> f64 {
        self.reputation
    }
}

/// Threat reporter that coordinates with P2P network
pub struct ThreatReporter {
    agent_id: String,
    evidence_collector: EvidenceCollector,
}

impl ThreatReporter {
    pub fn new(
        agent_id: String,
        config: AgentConfig,
        evidence_queue: tokio::sync::mpsc::UnboundedReceiver<ThreatEvidence>,
        blocklist_sender: Option<tokio::sync::mpsc::UnboundedSender<ThreatEvidence>>,
    ) -> Self {
        let evidence_collector = EvidenceCollector::new(agent_id.clone(), config, evidence_queue, blocklist_sender);
        
        Self {
            agent_id,
            evidence_collector,
        }
    }

    /// Start the reporting service
    pub async fn start_reporting(&mut self) -> Result<()> {
        log::info!("Starting threat reporting service...");
        self.evidence_collector.start_collection().await
    }

    /// Get current agent reputation
    pub fn get_reputation(&self) -> f64 {
        self.evidence_collector.get_reputation()
    }
}

impl ThreatType {
    /// Get string representation of threat type
    pub fn as_ref(&self) -> &'static str {
        match self {
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