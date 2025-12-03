use crate::{ThreatEvidence, ThreatType, ThreatLevel, error::{AgentError, Result}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Threat detection engine
pub struct ThreatDetector {
    /// Behavior baseline for anomaly detection
    behavior_baseline: HashMap<String, f64>,
    
    /// Known threat indicators
    threat_indicators: Vec<String>,
    
    /// Detection rules
    detection_rules: Vec<DetectionRule>,
}

impl ThreatDetector {
    pub fn new() -> Self {
        Self {
            behavior_baseline: HashMap::new(),
            threat_indicators: vec![
                "suspicious_user_agent".to_string(),
                "abnormal_request_pattern".to_string(),
                "known_malicious_ip".to_string(),
            ],
            detection_rules: vec![
                DetectionRule {
                    name: "ddos_protection".to_string(),
                    condition: "request_rate > 100/sec".to_string(),
                    threat_type: ThreatType::DDoS,
                    threat_level: ThreatLevel::Critical,
                },
                DetectionRule {
                    name: "malware_detection".to_string(),
                    condition: "file_hash_in_ioc".to_string(),
                    threat_type: ThreatType::Malware,
                    threat_level: ThreatLevel::Critical,
                },
                DetectionRule {
                    name: "suspicious_connection".to_string(),
                    condition: "connection_to_known_bad_ip".to_string(),
                    threat_type: ThreatType::SuspiciousConnection,
                    threat_level: ThreatLevel::Warning,
                },
            ],
        }
    }

    /// Detect threats from network flow data
    pub fn detect_threats_from_flow(&mut self, flow_data: &str) -> Vec<ThreatEvidence> {
        let mut detected_threats = Vec::new();
        
        // Apply detection rules
        for rule in &self.detection_rules {
            if self.evaluate_rule(rule, flow_data) {
                let threat = ThreatEvidence {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64,
                    source_ip: "unknown".to_string(), // Would be extracted from flow_data
                    target_ip: "local".to_string(),
                    threat_type: rule.threat_type.clone(),
                    threat_level: rule.threat_level,
                    context: format!("Triggered rule: {}", rule.name),
                    evidence_hash: crate::crypto::CryptoProvider::blake3_hash(flow_data.as_bytes()),
                    geolocation: "unknown".to_string(),
                    network_flow: flow_data.to_string(),
                    agent_id: "agent".to_string(), // Will be set by agent
                    reputation: 1.0, // Will be set by agent
                    compliance_tag: "global".to_string(), // Will be set by agent
                    region: "unknown".to_string(),
                };
                
                detected_threats.push(threat);
            }
        }
        
        // Check against known threat indicators
        for indicator in &self.threat_indicators {
            if flow_data.contains(indicator) {
                let threat = ThreatEvidence {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64,
                    source_ip: "unknown".to_string(),
                    target_ip: "local".to_string(),
                    threat_type: ThreatType::IoCMatch,
                    threat_level: ThreatLevel::Warning,
                    context: format!("Matched known threat indicator: {}", indicator),
                    evidence_hash: crate::crypto::CryptoProvider::blake3_hash(flow_data.as_bytes()),
                    geolocation: "unknown".to_string(),
                    network_flow: flow_data.to_string(),
                    agent_id: "agent".to_string(), // Will be set by agent
                    reputation: 1.0, // Will be set by agent
                    compliance_tag: "global".to_string(), // Will be set by agent
                    region: "unknown".to_string(),
                };
                
                detected_threats.push(threat);
            }
        }
        
        detected_threats
    }

    /// Detect anomalies in behavior
    pub fn detect_behavior_anomalies(&mut self, behavior_data: &str) -> Vec<ThreatEvidence> {
        let mut detected_threats = Vec::new();
        
        // Calculate behavior score
        let behavior_score = self.calculate_behavior_score(behavior_data);
        
        // If score is significantly different from baseline, flag as anomaly
        if behavior_score > 0.8 {  // Threshold for anomaly detection
            let threat = ThreatEvidence {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
                source_ip: "local".to_string(),
                target_ip: "local".to_string(),
                threat_type: ThreatType::AnomalousBehavior,
                threat_level: ThreatLevel::Info,
                context: format!("Behavior anomaly detected: score={:.2}", behavior_score),
                evidence_hash: crate::crypto::CryptoProvider::blake3_hash(behavior_data.as_bytes()),
                geolocation: "local".to_string(),
                network_flow: behavior_data.to_string(),
                agent_id: "agent".to_string(), // Will be set by agent
                reputation: 1.0, // Will be set by agent
                compliance_tag: "global".to_string(), // Will be set by agent
                region: "local".to_string(),
            };
            
            detected_threats.push(threat);
        }
        
        detected_threats
    }

    /// Evaluate a detection rule against data
    fn evaluate_rule(&self, rule: &DetectionRule, data: &str) -> bool {
        // Simple pattern matching for demonstration
        // In a real implementation, this would be more sophisticated
        match rule.name.as_str() {
            "ddos_protection" => data.contains("high_request_rate"),
            "malware_detection" => data.contains("malicious_hash"),
            "suspicious_connection" => data.contains("known_bad_ip"),
            _ => false,
        }
    }

    /// Calculate behavior score based on data
    fn calculate_behavior_score(&mut self, behavior_data: &str) -> f64 {
        // Simple scoring for demonstration
        // In a real implementation, this would use ML models
        let current_behavior = behavior_data.len() as f64;
        
        // Update baseline
        let key = "default".to_string();
        let baseline = self.behavior_baseline.entry(key).or_insert_with(|| current_behavior * 0.9);
        
        // Calculate deviation from baseline
        let deviation = (current_behavior - *baseline).abs() / (*baseline + 1.0);
        
        // Update baseline with weighted average
        *baseline = *baseline * 0.9 + current_behavior * 0.1;
        
        deviation
    }
}

/// Detection rule structure
#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub name: String,
    pub condition: String,
    pub threat_type: ThreatType,
    pub threat_level: ThreatLevel,
}

/// Behavior analyzer
pub struct BehaviorAnalyzer {
    /// Historical behavior data
    history: HashMap<String, Vec<f64>>,
    
    /// Anomaly detection threshold
    threshold: f64,
}

impl BehaviorAnalyzer {
    pub fn new(threshold: f64) -> Self {
        Self {
            history: HashMap::new(),
            threshold,
        }
    }

    /// Analyze behavior and detect anomalies
    pub fn analyze_behavior(&mut self, entity: &str, metric: f64) -> bool {
        let history = self.history.entry(entity.to_string()).or_insert_with(Vec::new);
        
        // Keep last 100 data points
        if history.len() >= 100 {
            history.remove(0);
        }
        
        history.push(metric);
        
        // Calculate mean and std dev
        if history.len() < 10 {
            return false; // Not enough data points
        }
        
        let mean = history.iter().sum::<f64>() / history.len() as f64;
        let variance = history.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / history.len() as f64;
        let std_dev = variance.sqrt();
        
        // Check if current metric is an anomaly
        (metric - mean).abs() > self.threshold * std_dev
    }
}