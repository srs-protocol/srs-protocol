use crate::{ThreatEvidence, ThreatLevel, error::{AgentError, Result}};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Credibility enhancement engine
pub struct CredibilityEngine {
    /// Track source reputation scores
    source_reputation: RwLock<HashMap<String, f64>>,
    
    /// Track IP reputation scores
    ip_reputation: RwLock<HashMap<String, f64>>,
    
    /// Track threat type accuracy scores
    threat_type_accuracy: RwLock<HashMap<String, (u64, u64)>>, // (correct_reports, total_reports)
    
    /// Configuration for credibility calculations
    config: CredibilityConfig,
}

/// Configuration for credibility calculations
#[derive(Debug, Clone)]
pub struct CredibilityConfig {
    /// Weight for source reputation (0.0-1.0)
    pub source_reputation_weight: f64,
    
    /// Weight for IP reputation (0.0-1.0)
    pub ip_reputation_weight: f64,
    
    /// Weight for historical accuracy (0.0-1.0)
    pub historical_accuracy_weight: f64,
    
    /// Weight for consensus verification (0.0-1.0)
    pub consensus_weight: f64,
    
    /// Minimum credibility threshold for high-confidence threats
    pub high_confidence_threshold: f64,
    
    /// Minimum credibility threshold for medium-confidence threats
    pub medium_confidence_threshold: f64,
    
    /// Decay factor for reputation over time (0.9-1.0)
    pub reputation_decay_factor: f64,
    
    /// Time window for recency factor in seconds
    pub recency_time_window: u64,
}

impl Default for CredibilityConfig {
    fn default() -> Self {
        Self {
            source_reputation_weight: 0.3,
            ip_reputation_weight: 0.25,
            historical_accuracy_weight: 0.25,
            consensus_weight: 0.2,
            high_confidence_threshold: 0.8,
            medium_confidence_threshold: 0.6,
            reputation_decay_factor: 0.99,
            recency_time_window: 86400, // 24 hours
        }
    }
}

impl CredibilityEngine {
    pub fn new(config: CredibilityConfig) -> Self {
        Self {
            source_reputation: RwLock::new(HashMap::new()),
            ip_reputation: RwLock::new(HashMap::new()),
            threat_type_accuracy: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Calculate credibility score for threat evidence
    pub async fn calculate_credibility_score(&self, evidence: &ThreatEvidence, consensus_confidence: Option<f64>) -> Result<f64> {
        let mut score = 0.0;
        let mut total_weight = 0.0;

        // 1. Source reputation component
        let source_rep_score = self.get_source_reputation(&evidence.agent_id).await;
        score += source_rep_score * self.config.source_reputation_weight;
        total_weight += self.config.source_reputation_weight;

        // 2. IP reputation component
        let ip_rep_score = self.get_ip_reputation(&evidence.source_ip).await;
        score += ip_rep_score * self.config.ip_reputation_weight;
        total_weight += self.config.ip_reputation_weight;

        // 3. Historical accuracy component (based on threat type)
        let threat_type_accuracy = self.get_threat_type_accuracy(&evidence.threat_type).await;
        score += threat_type_accuracy * self.config.historical_accuracy_weight;
        total_weight += self.config.historical_accuracy_weight;

        // 4. Consensus verification component (if available)
        if let Some(consensus_conf) = consensus_confidence {
            score += consensus_conf * self.config.consensus_weight;
            total_weight += self.config.consensus_weight;
        }

        // Normalize the score
        if total_weight > 0.0 {
            score /= total_weight;
        }

        // Apply recency factor (more recent reports have slightly higher credibility)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let time_diff = now as i64 - evidence.timestamp;
        let recency_factor = self.calculate_recency_factor(time_diff as u64);
        score *= recency_factor;

        // Ensure score is within bounds
        Ok(score.max(0.0).min(1.0))
    }

    /// Update credibility based on verification results
    pub async fn update_credibility(&self, evidence: &ThreatEvidence, is_accurate: bool) -> Result<()> {
        // Update source reputation
        {
            let mut source_reputation = self.source_reputation.write().await;
            let current_rep = source_reputation.entry(evidence.agent_id.clone()).or_insert(0.7); // Default to 0.7
            
            if is_accurate {
                *current_rep = (*current_rep * 0.9 + 1.0 * 0.1).min(1.0); // Boost with 10% weight
            } else {
                *current_rep = (*current_rep * 0.9 + 0.0 * 0.1).max(0.0); // Reduce with 10% weight
            }
        }

        // Update IP reputation
        {
            let mut ip_reputation = self.ip_reputation.write().await;
            let current_rep = ip_reputation.entry(evidence.source_ip.clone()).or_insert(0.5); // Default to 0.5
            
            if is_accurate {
                *current_rep = (*current_rep * 0.95 + 1.0 * 0.05).min(1.0); // Small update for IP
            } else {
                *current_rep = (*current_rep * 0.95 + 0.0 * 0.05).max(0.0);
            }
        }

        // Update threat type accuracy
        {
            let mut threat_type_accuracy = self.threat_type_accuracy.write().await;
            let threat_type_key = format!("{:?}", evidence.threat_type);
            let (correct, total) = threat_type_accuracy.entry(threat_type_key).or_insert((0, 0));
            
            *total += 1;
            if is_accurate {
                *correct += 1;
            }
        }

        Ok(())
    }

    /// Get source reputation
    async fn get_source_reputation(&self, source_id: &str) -> f64 {
        let source_reputation = self.source_reputation.read().await;
        
        // For upstream sources, provide a default high reputation
        if source_id.starts_with("upstream-") {
            return 0.9; // High trust for upstream feeds
        }
        
        *source_reputation.get(source_id).unwrap_or(&0.7) // Default to 0.7
    }

    /// Get IP reputation
    async fn get_ip_reputation(&self, ip: &str) -> f64 {
        let ip_reputation = self.ip_reputation.read().await;
        *ip_reputation.get(ip).unwrap_or(&0.5) // Default to 0.5
    }

    /// Get threat type accuracy
    async fn get_threat_type_accuracy(&self, threat_type: &crate::ThreatType) -> f64 {
        let threat_type_accuracy = self.threat_type_accuracy.read().await;
        let threat_type_key = format!("{:?}", threat_type);
        
        if let Some((correct, total)) = threat_type_accuracy.get(&threat_type_key) {
            if *total > 0 {
                *correct as f64 / *total as f64
            } else {
                0.7 // Default accuracy for new threat types
            }
        } else {
            0.7 // Default accuracy
        }
    }

    /// Calculate recency factor (more recent = higher credibility)
    fn calculate_recency_factor(&self, time_diff_seconds: u64) -> f64 {
        if time_diff_seconds > self.config.recency_time_window {
            // If older than the time window, credibility decreases
            let decay = 1.0 - (time_diff_seconds as f64 / self.config.recency_time_window as f64).min(1.0);
            0.5 + decay * 0.5 // Range from 0.5 to 1.0
        } else {
            // If recent, maintain high credibility
            1.0
        }
    }

    /// Enhance threat evidence with credibility information
    pub async fn enhance_threat_evidence(&self, mut evidence: ThreatEvidence, consensus_confidence: Option<f64>) -> Result<ThreatEvidence> {
        let credibility_score = self.calculate_credibility_score(&evidence, consensus_confidence).await?;
        
        // Adjust threat level based on credibility score
        let adjusted_threat_level = self.adjust_threat_level_by_credential(&evidence.threat_level, credibility_score);
        
        // Update the evidence with credibility-enhanced information
        evidence.threat_level = adjusted_threat_level;
        
        // Update reputation fields
        evidence.reputation = credibility_score;
        
        // Add credibility context
        evidence.context = format!("{} [CREDIBILITY: {:.2}]", evidence.context, credibility_score);
        
        Ok(evidence)
    }

    /// Adjust threat level based on credibility score
    fn adjust_threat_level_by_credential(&self, original_level: ThreatLevel, credibility_score: f64) -> ThreatLevel {
        if credibility_score >= self.config.high_confidence_threshold {
            // High credibility - maintain or increase threat level
            original_level
        } else if credibility_score >= self.config.medium_confidence_threshold {
            // Medium credibility - possibly reduce threat level
            match original_level {
                ThreatLevel::Emergency => ThreatLevel::Critical,
                ThreatLevel::Critical => ThreatLevel::Warning,
                ThreatLevel::Warning => ThreatLevel::Info,
                ThreatLevel::Info => ThreatLevel::Info,
            }
        } else {
            // Low credibility - reduce threat level
            ThreatLevel::Info
        }
    }

    /// Batch process multiple threat evidences for credibility enhancement
    pub async fn batch_enhance_threat_evidence(
        &self,
        evidences: Vec<(ThreatEvidence, Option<f64>)>
    ) -> Result<Vec<ThreatEvidence>> {
        let mut enhanced_evidences = Vec::new();
        
        for (evidence, consensus_confidence) in evidences {
            let enhanced = self.enhance_threat_evidence(evidence, consensus_confidence).await?;
            enhanced_evidences.push(enhanced);
        }
        
        Ok(enhanced_evidences)
    }

    /// Get current credibility metrics
    pub async fn get_metrics(&self) -> CredibilityMetrics {
        let source_reputation = self.source_reputation.read().await;
        let ip_reputation = self.ip_reputation.read().await;
        let threat_type_accuracy = self.threat_type_accuracy.read().await;
        
        CredibilityMetrics {
            total_sources_tracked: source_reputation.len(),
            total_ips_tracked: ip_reputation.len(),
            total_threat_types_tracked: threat_type_accuracy.len(),
            avg_source_reputation: source_reputation.values().sum::<f64>() / std::cmp::max(1, source_reputation.len()) as f64,
            avg_ip_reputation: ip_reputation.values().sum::<f64>() / std::cmp::max(1, ip_reputation.len()) as f64,
        }
    }
}

/// Credibility metrics for monitoring
#[derive(Debug, Clone)]
pub struct CredibilityMetrics {
    pub total_sources_tracked: usize,
    pub total_ips_tracked: usize,
    pub total_threat_types_tracked: usize,
    pub avg_source_reputation: f64,
    pub avg_ip_reputation: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ThreatEvidence, ThreatType, ThreatLevel};

    #[tokio::test]
    async fn test_credibility_engine_creation() {
        let config = CredibilityConfig::default();
        let engine = CredibilityEngine::new(config);
        
        assert_eq!(engine.config.source_reputation_weight, 0.3);
    }

    #[tokio::test]
    async fn test_calculate_credibility_score() {
        let config = CredibilityConfig::default();
        let engine = CredibilityEngine::new(config);
        
        let evidence = ThreatEvidence {
            id: "test".to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            source_ip: "192.168.1.100".to_string(),
            target_ip: "10.0.0.1".to_string(),
            threat_type: ThreatType::Malware,
            threat_level: ThreatLevel::Critical,
            context: "Test threat".to_string(),
            evidence_hash: crate::crypto::CryptoProvider::blake3_hash(b"test"),
            geolocation: "unknown".to_string(),
            network_flow: "TCP".to_string(),
            agent_id: "test-agent".to_string(),
            reputation: 0.8,
            compliance_tag: "global".to_string(),
            region: "test".to_string(),
        };

        let score = engine.calculate_credibility_score(&evidence, Some(0.9)).await.unwrap();
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[tokio::test]
    async fn test_update_credibility() {
        let config = CredibilityConfig::default();
        let engine = CredibilityEngine::new(config);
        
        let evidence = ThreatEvidence {
            id: "test".to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            source_ip: "192.168.1.101".to_string(),
            target_ip: "10.0.0.1".to_string(),
            threat_type: ThreatType::Malware,
            threat_level: ThreatLevel::Critical,
            context: "Test threat".to_string(),
            evidence_hash: crate::crypto::CryptoProvider::blake3_hash(b"test"),
            geolocation: "unknown".to_string(),
            network_flow: "TCP".to_string(),
            agent_id: "test-agent-2".to_string(),
            reputation: 0.8,
            compliance_tag: "global".to_string(),
            region: "test".to_string(),
        };

        // Initially should have default reputation
        let initial_rep = engine.get_source_reputation("test-agent-2").await;
        assert_eq!(initial_rep, 0.7);

        // Update with accurate information
        engine.update_credibility(&evidence, true).await.unwrap();
        
        // Should have higher reputation now
        let updated_rep = engine.get_source_reputation("test-agent-2").await;
        assert!(updated_rep > 0.7);
    }
}