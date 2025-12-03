use crate::{ThreatEvidence, ThreatType, ThreatLevel, error::{AgentError, Result}};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::sync::RwLock;
use tokio::time::sleep;
use uuid::Uuid;

/// Consensus verification configuration
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    pub min_verifiers: u32,           // Minimum number of verifiers needed for consensus
    pub verification_timeout: u64,    // Timeout for verification in seconds
    pub reputation_threshold: f64,    // Minimum reputation threshold for valid verification
    pub consensus_threshold: f64,     // Percentage of verifiers needed for consensus (0.0-1.0)
    pub max_consensus_attempts: u32,  // Maximum number of consensus attempts before giving up
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            min_verifiers: 3,
            verification_timeout: 30,      // 30 seconds
            reputation_threshold: 0.7,     // 70% reputation threshold
            consensus_threshold: 0.6,      // 60% consensus needed
            max_consensus_attempts: 5,
        }
    }
}

/// Verification request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    pub request_id: String,
    pub evidence_id: String,
    pub evidence: ThreatEvidence,
    pub requesting_agent: String,
    pub timestamp: i64,
    pub verification_threshold: u32,
    pub verifiers: Vec<String>,        // List of agents requested to verify
    pub responses: Vec<VerificationResponse>,
    pub status: VerificationStatus,
}

/// Verification response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResponse {
    pub request_id: String,
    pub evidence_id: String,
    pub verifying_agent: String,
    pub verdict: bool,                 // true for confirmed, false for disputed
    pub confidence: f64,               // Confidence level of the verification (0.0-1.0)
    pub justification: String,         // Reason for the verdict
    pub timestamp: i64,
    pub signature: String,             // Digital signature of the verifying agent
}

/// Verification status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationStatus {
    Pending,
    InProgress,
    Verified,
    Rejected,
    Expired,
    ConsensusReached,
    ConsensusFailed,
}

/// Consensus verification engine
pub struct ConsensusEngine {
    config: ConsensusConfig,
    pending_requests: RwLock<HashMap<String, VerificationRequest>>,
    verification_cache: RwLock<HashMap<String, ConsensusResult>>,
    local_agent_id: String,
}

/// Result of consensus verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    pub evidence_id: String,
    pub consensus_verdict: bool,       // true if threat is verified, false if disputed
    pub confidence_score: f64,         // Overall confidence score (0.0-1.0)
    pub verified_by: Vec<String>,      // Agents that verified the threat
    pub disputed_by: Vec<String>,      // Agents that disputed the threat
    pub total_verifiers: usize,        // Total number of verifiers
    pub consensus_percentage: f64,     // Percentage of verifiers that agreed
    pub timestamp: i64,
}

impl ConsensusEngine {
    pub fn new(config: ConsensusConfig, local_agent_id: String) -> Self {
        Self {
            config,
            pending_requests: RwLock::new(HashMap::new()),
            verification_cache: RwLock::new(HashMap::new()),
            local_agent_id,
        }
    }

    /// Submit evidence for consensus verification
    pub async fn submit_for_verification(&self, evidence: ThreatEvidence) -> Result<VerificationRequest> {
        let request_id = format!("consensus-{}", Uuid::new_v4());
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let verification_request = VerificationRequest {
            request_id: request_id.clone(),
            evidence_id: evidence.id.clone(),
            evidence: evidence.clone(),
            requesting_agent: self.local_agent_id.clone(),
            timestamp,
            verification_threshold: self.config.min_verifiers,
            verifiers: Vec::new(),        // Will be populated by the consensus mechanism
            responses: Vec::new(),
            status: VerificationStatus::Pending,
        };

        // Store the request
        {
            let mut requests = self.pending_requests.write().await;
            requests.insert(request_id.clone(), verification_request.clone());
        }

        log::info!("Submitted evidence {} for consensus verification", evidence.id);
        
        Ok(verification_request)
    }

    /// Verify evidence from another agent
    pub async fn verify_evidence(&self, request: &VerificationRequest) -> Result<VerificationResponse> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Perform local verification of the evidence
        let (verdict, confidence, justification) = self.local_verify_evidence(&request.evidence).await;

        let response = VerificationResponse {
            request_id: request.request_id.clone(),
            evidence_id: request.evidence_id.clone(),
            verifying_agent: self.local_agent_id.clone(),
            verdict,
            confidence,
            justification,
            timestamp,
            signature: self.sign_verification_response(&request.request_id, verdict, confidence)?,
        };

        // Update the request with our response
        {
            let mut requests = self.pending_requests.write().await;
            if let Some(mut req) = requests.get_mut(&request.request_id) {
                req.responses.push(response.clone());
                
                // Update status based on responses
                if req.responses.len() >= req.verification_threshold as usize {
                    req.status = VerificationStatus::InProgress;
                }
            }
        }

        log::info!("Submitted verification response for evidence {}: verdict={}, confidence={}", 
                  request.evidence_id, verdict, confidence);

        Ok(response)
    }

    /// Perform local verification of evidence
    async fn local_verify_evidence(&self, evidence: &ThreatEvidence) -> (bool, f64, String) {
        // Check if this evidence matches known threat patterns
        let mut confidence = 0.5; // Base confidence
        let mut justification = String::new();

        // Check if this is from a trusted upstream source
        if evidence.agent_id.starts_with("upstream-") {
            confidence += 0.2; // Upstream sources have higher base trust
            justification.push_str(&format!("Upstream source: {}; ", evidence.agent_id));
        }

        // Check threat level
        match evidence.threat_level {
            ThreatLevel::Info => confidence -= 0.1,
            ThreatLevel::Warning => confidence += 0.1,
            ThreatLevel::Critical => confidence += 0.2,
            ThreatLevel::Emergency => confidence += 0.3,
        }

        // Check if source IP is in known threat databases (simulated)
        if self.is_known_threat_ip(&evidence.source_ip).await {
            confidence += 0.3;
            justification.push_str("Known threat IP; ");
        }

        // Check if threat type is common/expected
        match evidence.threat_type {
            ThreatType::IoCMatch => confidence += 0.1,
            ThreatType::Malware => confidence += 0.2,
            ThreatType::DDoS => confidence += 0.15,
            ThreatType::APT => confidence += 0.25,
            _ => confidence += 0.05,
        }

        // Ensure confidence is within bounds
        confidence = confidence.max(0.0).min(1.0);

        // Determine verdict based on confidence threshold
        let verdict = confidence > 0.6;

        justification.push_str(&format!("Calculated confidence: {:.2}", confidence));

        (verdict, confidence, justification)
    }

    /// Check if an IP is in known threat databases (simulated)
    async fn is_known_threat_ip(&self, ip: &str) -> bool {
        // In a real implementation, this would check against threat intelligence feeds
        // For now, we'll simulate by checking against a small list of known bad IPs
        let known_threat_ips = [
            "192.168.1.100",
            "10.0.0.10",
            "8.8.8.8",  // Example IP for testing
        ];

        known_threat_ips.contains(&ip)
    }

    /// Check for consensus on a verification request
    pub async fn check_consensus(&self, request_id: &str) -> Result<ConsensusResult> {
        let requests = self.pending_requests.read().await;
        let request = requests.get(request_id)
            .ok_or_else(|| AgentError::InternalError(format!("Verification request {} not found", request_id)))?
            .clone();
        drop(requests);

        let responses = &request.responses;
        let total_responses = responses.len();
        
        if total_responses == 0 {
            return Err(AgentError::InternalError("No verification responses received".to_string()));
        }

        // Calculate consensus
        let verified_count = responses.iter()
            .filter(|resp| resp.verdict)
            .count();
        
        let disputed_count = total_responses - verified_count;
        let consensus_percentage = verified_count as f64 / total_responses as f64;
        let consensus_verdict = consensus_percentage >= self.config.consensus_threshold;

        let verified_by: Vec<String> = responses.iter()
            .filter(|resp| resp.verdict)
            .map(|resp| resp.verifying_agent.clone())
            .collect();

        let disputed_by: Vec<String> = responses.iter()
            .filter(|resp| !resp.verdict)
            .map(|resp| resp.verifying_agent.clone())
            .collect();

        // Calculate average confidence
        let avg_confidence = if !responses.is_empty() {
            responses.iter()
                .map(|resp| resp.confidence)
                .sum::<f64>() / responses.len() as f64
        } else {
            0.0
        };

        let consensus_result = ConsensusResult {
            evidence_id: request.evidence_id.clone(),
            consensus_verdict,
            confidence_score: avg_confidence,
            verified_by,
            disputed_by,
            total_verifiers: total_responses,
            consensus_percentage,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        };

        // Update request status
        {
            let mut requests = self.pending_requests.write().await;
            if let Some(req) = requests.get_mut(request_id) {
                req.status = if consensus_verdict {
                    VerificationStatus::ConsensusReached
                } else {
                    VerificationStatus::ConsensusFailed
                };
            }
        }

        // Cache the result
        {
            let mut cache = self.verification_cache.write().await;
            cache.insert(request.evidence_id.clone(), consensus_result.clone());
        }

        Ok(consensus_result)
    }

    /// Process multiple evidence items for consensus (used for local + upstream correlation)
    pub async fn process_evidence_correlation(
        &self,
        local_evidence: &[ThreatEvidence],
        upstream_evidence: &[ThreatEvidence],
    ) -> Result<Vec<(ThreatEvidence, ConsensusResult)>> {
        let mut correlated_results = Vec::new();

        // Correlate local and upstream evidence
        for local_item in local_evidence {
            for upstream_item in upstream_evidence {
                // Check if these items are related (same IP, same threat pattern, etc.)
                if self.is_correlated_evidence(local_item, upstream_item) {
                    // Combine the evidence into a new item for verification
                    let combined_evidence = self.combine_evidence(local_item, upstream_item);
                    
                    // Submit for consensus verification
                    let verification_request = self.submit_for_verification(combined_evidence.clone()).await?;
                    let consensus_result = self.check_consensus(&verification_request.request_id).await?;
                    
                    correlated_results.push((combined_evidence, consensus_result));
                }
            }
        }

        // Also process upstream evidence individually
        for upstream_item in upstream_evidence {
            if !local_evidence.iter().any(|local| {
                self.is_correlated_evidence(local, upstream_item)
            }) {
                // Submit for consensus verification
                let verification_request = self.submit_for_verification(upstream_item.clone()).await?;
                let consensus_result = self.check_consensus(&verification_request.request_id).await?;
                
                correlated_results.push((upstream_item.clone(), consensus_result));
            }
        }

        Ok(correlated_results)
    }

    /// Check if two evidence items are correlated
    fn is_correlated_evidence(&self, evidence1: &ThreatEvidence, evidence2: &ThreatEvidence) -> bool {
        // Check if they have the same source IP
        if !evidence1.source_ip.is_empty() && !evidence2.source_ip.is_empty() {
            if evidence1.source_ip == evidence2.source_ip {
                return true;
            }
        }

        // Check if they have similar threat patterns
        if !evidence1.network_flow.is_empty() && !evidence2.network_flow.is_empty() {
            if evidence1.network_flow == evidence2.network_flow {
                return true;
            }
        }

        // Check if they have similar context
        if !evidence1.context.is_empty() && !evidence2.context.is_empty() {
            if evidence1.context.contains(&evidence2.context) || evidence2.context.contains(&evidence1.context) {
                return true;
            }
        }

        // Additional correlation checks can be added here
        false
    }

    /// Combine two evidence items into one
    fn combine_evidence(&self, evidence1: &ThreatEvidence, evidence2: &ThreatEvidence) -> ThreatEvidence {
        // Create a new evidence item that combines information from both
        ThreatEvidence {
            id: format!("combined-{}-{}", evidence1.id, evidence2.id),
            timestamp: std::cmp::max(evidence1.timestamp, evidence2.timestamp),
            source_ip: if !evidence1.source_ip.is_empty() { evidence1.source_ip.clone() } else { evidence2.source_ip.clone() },
            target_ip: if !evidence1.target_ip.is_empty() { evidence1.target_ip.clone() } else { evidence2.target_ip.clone() },
            threat_type: if evidence1.threat_type != ThreatType::Unknown { evidence1.threat_type.clone() } else { evidence2.threat_type.clone() },
            threat_level: std::cmp::max(evidence1.threat_level, evidence2.threat_level), // Take higher threat level
            context: format!("{} | Combined with upstream: {}", evidence1.context, evidence2.context),
            evidence_hash: crate::crypto::CryptoProvider::blake3_hash(
                format!("{}-{}", evidence1.evidence_hash, evidence2.evidence_hash).as_bytes()
            ),
            geolocation: if !evidence1.geolocation.is_empty() { evidence1.geolocation.clone() } else { evidence2.geolocation.clone() },
            network_flow: if !evidence1.network_flow.is_empty() { evidence1.network_flow.clone() } else { evidence2.network_flow.clone() },
            agent_id: format!("combined-{}-{}", evidence1.agent_id, evidence2.agent_id),
            reputation: (evidence1.reputation + evidence2.reputation) / 2.0, // Average reputation
            compliance_tag: evidence1.compliance_tag.clone(), // Use first evidence compliance tag
            region: evidence1.region.clone(), // Use first evidence region
        }
    }

    /// Sign a verification response
    fn sign_verification_response(&self, request_id: &str, verdict: bool, confidence: f64) -> Result<String> {
        // In a real implementation, this would create a cryptographic signature
        // For now, we'll create a simple hash-based signature
        let signature_data = format!("{}-{}-{:.2}-{}", request_id, verdict, confidence, self.local_agent_id);
        Ok(crate::crypto::CryptoProvider::blake3_hash(signature_data.as_bytes()))
    }

    /// Get cached verification results
    pub async fn get_cached_result(&self, evidence_id: &str) -> Option<ConsensusResult> {
        let cache = self.verification_cache.read().await;
        cache.get(evidence_id).cloned()
    }

    /// Periodically clean up old requests
    pub async fn cleanup_old_requests(&self) -> Result<()> {
        let mut requests = self.pending_requests.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        requests.retain(|_, request| {
            // Keep requests that are not expired (older than verification_timeout seconds)
            now - request.timestamp < self.config.verification_timeout as i64
        });

        log::debug!("Cleaned up {} old verification requests", 
                   requests.len() - self.pending_requests.read().await.len());

        Ok(())
    }

    /// Get current configuration
    pub fn get_config(&self) -> ConsensusConfig {
        self.config.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ThreatEvidence;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn test_consensus_engine_creation() {
        let config = ConsensusConfig::default();
        let engine = ConsensusEngine::new(config, "test-agent".to_string());
        
        assert_eq!(engine.get_config().min_verifiers, 3);
    }

    #[tokio::test]
    async fn test_submit_for_verification() {
        let config = ConsensusConfig::default();
        let engine = ConsensusEngine::new(config, "test-agent".to_string());
        
        let evidence = ThreatEvidence {
            id: "test-evidence".to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            source_ip: "192.168.1.100".to_string(),
            target_ip: "10.0.0.1".to_string(),
            threat_type: crate::ThreatType::Malware,
            threat_level: crate::ThreatLevel::Critical,
            context: "Test threat evidence".to_string(),
            evidence_hash: crate::crypto::CryptoProvider::blake3_hash(b"test-data"),
            geolocation: "unknown".to_string(),
            network_flow: "TCP".to_string(),
            agent_id: "test-agent".to_string(),
            reputation: 0.9,
            compliance_tag: "global".to_string(),
            region: "test-region".to_string(),
        };

        let result = engine.submit_for_verification(evidence).await;
        assert!(result.is_ok());
    }
}