use crate::{ThreatEvidence, ThreatType, ThreatLevel, error::{AgentError, Result}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};
use reqwest;
use url::Url;

/// Upstream threat intelligence source configuration
#[derive(Debug, Clone)]
pub struct UpstreamSourceConfig {
    pub name: String,
    pub url: String,
    pub auth_token: Option<String>,
    pub enabled: bool,
    pub update_interval: u64, // in seconds
    pub threat_level_mapping: HashMap<String, ThreatLevel>,
}

/// Upstream threat intelligence aggregator
pub struct ThreatIntelAggregator {
    sources: Vec<UpstreamSourceConfig>,
    client: reqwest::Client,
    last_update_times: HashMap<String, i64>,
}

impl ThreatIntelAggregator {
    pub fn new() -> Self {
        Self {
            sources: vec![
                Self::create_cisa_ais_config(),  // CISA AIS as primary source
            ],
            client: reqwest::Client::new(),
            last_update_times: HashMap::new(),
        }
    }

    /// Create default CISA AIS configuration
    fn create_cisa_ais_config() -> UpstreamSourceConfig {
        let mut threat_level_mapping = HashMap::new();
        threat_level_mapping.insert("low".to_string(), ThreatLevel::Info);
        threat_level_mapping.insert("medium".to_string(), ThreatLevel::Warning);
        threat_level_mapping.insert("high".to_string(), ThreatLevel::Critical);
        threat_level_mapping.insert("critical".to_string(), ThreatLevel::Emergency);

        UpstreamSourceConfig {
            name: "CISA_AIS".to_string(),
            url: "https://ais2.cisa.gov/taxii2/".to_string(), // Placeholder - actual TAXII endpoint
            auth_token: None, // Would need actual CISA AIS credentials
            enabled: false,   // Disabled by default, requires proper credentials
            update_interval: 300, // 5 minutes
            threat_level_mapping,
        }
    }

    /// Add an upstream source
    pub fn add_source(&mut self, config: UpstreamSourceConfig) {
        self.sources.push(config);
    }

    /// Fetch threat intelligence from all enabled sources
    pub async fn fetch_all_sources(&self) -> Result<Vec<ThreatEvidence>> {
        let mut all_threats = Vec::new();

        for source in &self.sources {
            if !source.enabled {
                continue;
            }

            match self.fetch_source(source).await {
                Ok(threats) => all_threats.extend(threats),
                Err(e) => {
                    log::warn!("Failed to fetch from upstream source '{}': {}", source.name, e);
                }
            }
        }

        Ok(all_threats)
    }

    /// Fetch threat intelligence from a specific source
    async fn fetch_source(&self, source: &UpstreamSourceConfig) -> Result<Vec<ThreatEvidence>> {
        log::info!("Fetching threat intelligence from source: {}", source.name);

        // Create a unique ID for this fetch operation
        let fetch_id = format!("{}_{}", source.name, SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs());

        // For CISA AIS (TAXII), we would need to implement proper TAXII client functionality
        // For now, we'll simulate the data fetch for demonstration purposes
        if source.name == "CISA_AIS" {
            self.fetch_cisa_ais_data(source, &fetch_id).await
        } else {
            // For other sources, we'll implement a generic fetch mechanism
            self.fetch_generic_source(source, &fetch_id).await
        }
    }

    /// Fetch data from CISA AIS (TAXII 2.1 compatible implementation)
    async fn fetch_cisa_ais_data(&self, source: &UpstreamSourceConfig, fetch_id: &str) -> Result<Vec<ThreatEvidence>> {
        log::info!("Fetching CISA AIS data for fetch ID: {}", fetch_id);

        // In a real implementation, this would be a proper TAXII 2.1 client
        // For demonstration, we'll simulate a TAXII response with STIX objects
        let mut threats = Vec::new();

        // Simulate STIX objects that would be received from CISA AIS
        // This is a simplified version - real STIX objects are more complex
        let simulated_stix_threats = [
            r#"{
                "type": "indicator",
                "id": "indicator--12345",
                "pattern": "[ipv4-addr:value = '192.168.1.100']",
                "pattern_type": "stix",
                "labels": ["malicious-activity"],
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "name": "CISA Alert: Malicious IP",
                "description": "IP address associated with known malicious activity",
                "confidence": 85
            }"#,
            r#"{
                "type": "indicator", 
                "id": "indicator--67890",
                "pattern": "[file:hashes.'SHA-256' = 'abc123...']",
                "pattern_type": "stix",
                "labels": ["malware"],
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z", 
                "name": "CISA Alert: Malware Hash",
                "description": "Malware hash associated with recent threat campaign",
                "confidence": 90
            }"#
        ];

        for stix_str in &simulated_stix_threats {
            // Parse the STIX object and convert to ThreatEvidence
            if let Ok(stix_obj) = serde_json::from_str::<serde_json::Value>(stix_str) {
                if let Some(threat_evidence) = self.convert_stix_to_threat_evidence(&stix_obj, source, fetch_id) {
                    threats.push(threat_evidence);
                }
            }
        }

        log::info!("Retrieved {} threats from CISA AIS", threats.len());
        Ok(threats)
    }

    /// Fetch data from a generic source (could be any threat feed)
    async fn fetch_generic_source(&self, source: &UpstreamSourceConfig, fetch_id: &str) -> Result<Vec<ThreatEvidence>> {
        log::info!("Fetching from generic source: {}", source.name);

        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(token) = &source.auth_token {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
                    .map_err(|e| AgentError::IoError(format!("Invalid auth token: {}", e)))?,
            );
        }

        let response = self
            .client
            .get(&source.url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| AgentError::IoError(format!("Failed to fetch from {}: {}", source.name, e)))?;

        if !response.status().is_success() {
            return Err(AgentError::IoError(format!(
                "HTTP error {} from {}",
                response.status(),
                source.name
            )));
        }

        let text = response
            .text()
            .await
            .map_err(|e| AgentError::IoError(format!("Failed to read response from {}: {}", source.name, e)))?;

        // Parse the response based on the content type
        let threats = self.parse_generic_threat_feed(&text, source, fetch_id)?;
        
        log::info!("Retrieved {} threats from generic source: {}", threats.len(), source.name);
        Ok(threats)
    }

    /// Convert STIX object to internal ThreatEvidence format
    fn convert_stix_to_threat_evidence(&self, stix_obj: &serde_json::Value, source: &UpstreamSourceConfig, fetch_id: &str) -> Option<ThreatEvidence> {
        let threat_type = match stix_obj.get("labels").and_then(|v| v.as_array()) {
            Some(labels) => {
                for label in labels {
                    if let Some(label_str) = label.as_str() {
                        match label_str {
                            "malicious-activity" => ThreatType::SuspiciousConnection,
                            "malware" => ThreatType::Malware,
                            "apt" => ThreatType::APT,
                            "ddos" => ThreatType::DDoS,
                            _ => ThreatType::IoCMatch,
                        }
                    }
                }
                ThreatType::IoCMatch // default
            },
            None => ThreatType::IoCMatch,
        };

        let threat_level = match stix_obj.get("confidence").and_then(|v| v.as_number()) {
            Some(conf) => {
                let conf_val = conf.as_u64().unwrap_or(50) as u8;
                if conf_val < 50 {
                    ThreatLevel::Info
                } else if conf_val < 75 {
                    ThreatLevel::Warning
                } else if conf_val < 90 {
                    ThreatLevel::Critical
                } else {
                    ThreatLevel::Emergency
                }
            },
            None => ThreatLevel::Warning,
        };

        // Extract indicator pattern to identify the threat
        let pattern = stix_obj.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
        let description = stix_obj.get("description").and_then(|v| v.as_str()).unwrap_or("");
        
        // Extract IP address if present in the pattern
        let source_ip = if pattern.contains("ipv4-addr:value") {
            // This is a simplified extraction - in reality, STIX patterns are more complex
            extract_ip_from_pattern(pattern).unwrap_or("unknown".to_string())
        } else {
            "unknown".to_string()
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Create a unique ID for this threat
        let threat_id = format!("{}_{}", 
            stix_obj.get("id").and_then(|v| v.as_str()).unwrap_or("unknown"), 
            timestamp
        );

        Some(ThreatEvidence {
            id: threat_id,
            timestamp,
            source_ip,
            target_ip: "global".to_string(),
            threat_type,
            threat_level,
            context: format!("Upstream source: {} - {}", source.name, description),
            evidence_hash: crate::crypto::CryptoProvider::blake3_hash(
                format!("{}-{}", fetch_id, pattern).as_bytes()
            ),
            geolocation: "unknown".to_string(),
            network_flow: pattern.to_string(),
            agent_id: format!("upstream-{}", source.name),
            reputation: 0.95, // Upstream sources typically have high reputation
            compliance_tag: "upstream".to_string(),
            region: "global".to_string(),
        })
    }

    /// Parse generic threat feed (JSON format)
    fn parse_generic_threat_feed(&self, content: &str, source: &UpstreamSourceConfig, fetch_id: &str) -> Result<Vec<ThreatEvidence>> {
        let mut threats = Vec::new();

        // Attempt to parse as JSON array
        match serde_json::from_str::<Vec<serde_json::Value>>(content) {
            Ok(threat_objects) => {
                for threat_obj in threat_objects {
                    if let Some(threat_evidence) = self.convert_generic_to_threat_evidence(&threat_obj, source, fetch_id) {
                        threats.push(threat_evidence);
                    }
                }
            }
            Err(_) => {
                // If not an array, try as single object
                if let Ok(threat_obj) = serde_json::from_str::<serde_json::Value>(content) {
                    if let Some(threat_evidence) = self.convert_generic_to_threat_evidence(&threat_obj, source, fetch_id) {
                        threats.push(threat_evidence);
                    }
                } else {
                    // If not JSON, try parsing as newline-delimited indicators
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            if let Some(threat_evidence) = self.parse_line_as_indicator(trimmed, source, fetch_id) {
                                threats.push(threat_evidence);
                            }
                        }
                    }
                }
            }
        }

        Ok(threats)
    }

    /// Convert generic threat object to ThreatEvidence
    fn convert_generic_to_threat_evidence(&self, threat_obj: &serde_json::Value, source: &UpstreamSourceConfig, fetch_id: &str) -> Option<ThreatEvidence> {
        // Extract fields based on common threat feed formats
        let source_ip = threat_obj.get("ip").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let threat_type_str = threat_obj.get("type").and_then(|v| v.as_str()).unwrap_or("unknown");
        let threat_level_str = threat_obj.get("level").and_then(|v| v.as_str()).unwrap_or("warning");
        let description = threat_obj.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();

        let threat_type = match threat_type_str {
            "malware" => ThreatType::Malware,
            "c2" => ThreatType::SuspiciousConnection,
            "phishing" => ThreatType::SuspiciousConnection,
            "scanner" => ThreatType::SuspiciousConnection,
            "exploit" => ThreatType::Exploit,
            "apt" => ThreatType::APT,
            _ => ThreatType::IoCMatch,
        };

        let threat_level = match threat_level_str {
            "info" | "low" => ThreatLevel::Info,
            "warning" | "medium" => ThreatLevel::Warning,
            "critical" | "high" => ThreatLevel::Critical,
            "emergency" | "severe" => ThreatLevel::Emergency,
            _ => ThreatLevel::Warning,
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let threat_id = format!("{}_{}_{}", source.name, threat_obj.get("id").and_then(|v| v.as_str()).unwrap_or("unknown"), timestamp);

        Some(ThreatEvidence {
            id: threat_id,
            timestamp,
            source_ip: source_ip.clone(),
            target_ip: "global".to_string(),
            threat_type,
            threat_level,
            context: format!("Upstream source: {} - {}", source.name, description),
            evidence_hash: crate::crypto::CryptoProvider::blake3_hash(
                format!("{}-{}-{}", fetch_id, source_ip, description).as_bytes()
            ),
            geolocation: "unknown".to_string(),
            network_flow: threat_obj.to_string(),
            agent_id: format!("upstream-{}", source.name),
            reputation: 0.90, // High reputation for upstream sources
            compliance_tag: "upstream".to_string(),
            region: "global".to_string(),
        })
    }

    /// Parse a single line as an indicator (common format for threat feeds)
    fn parse_line_as_indicator(&self, line: &str, source: &UpstreamSourceConfig, fetch_id: &str) -> Option<ThreatEvidence> {
        // Check if it's an IP address
        if is_valid_ip(line) {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            return Some(ThreatEvidence {
                id: format!("upstream-{}-{}-{}", source.name, line, timestamp),
                timestamp,
                source_ip: line.to_string(),
                target_ip: "global".to_string(),
                threat_type: ThreatType::IoCMatch,
                threat_level: ThreatLevel::Warning,
                context: format!("Upstream source: {} - Known malicious IP", source.name),
                evidence_hash: crate::crypto::CryptoProvider::blake3_hash(
                    format!("{}-{}", fetch_id, line).as_bytes()
                ),
                geolocation: "unknown".to_string(),
                network_flow: line.to_string(),
                agent_id: format!("upstream-{}", source.name),
                reputation: 0.85,
                compliance_tag: "upstream".to_string(),
                region: "global".to_string(),
            });
        }

        // Could add more parsing logic for other indicator types (URLs, hashes, etc.)
        None
    }

    /// Start periodic fetching of threat intelligence
    pub async fn start_periodic_fetch(&self) -> Result<()> {
        loop {
            match self.fetch_all_sources().await {
                Ok(threats) => {
                    log::info!("Fetched {} threats from upstream sources", threats.len());
                    // In a real implementation, these would be processed further
                    // For example, sent to the consensus mechanism
                }
                Err(e) => {
                    log::error!("Error fetching upstream threat intelligence: {}", e);
                }
            }

            // Wait for the minimum update interval before next fetch
            sleep(Duration::from_secs(60)).await; // Check every minute
        }
    }

    /// Get the current configuration of upstream sources
    pub fn get_sources_config(&self) -> Vec<UpstreamSourceConfig> {
        self.sources.clone()
    }
}

/// Helper function to extract IP address from STIX pattern
fn extract_ip_from_pattern(pattern: &str) -> Option<String> {
    // Simple pattern: [ipv4-addr:value = '192.168.1.100']
    // In a real implementation, this would use a proper STIX pattern parser
    if let Some(start) = pattern.find(''') {
        if let Some(end) = pattern[start + 1..].find(''') {
            let ip = &pattern[start + 1..start + 1 + end];
            if is_valid_ip(ip) {
                return Some(ip.to_string());
            }
        }
    }
    None
}

/// Helper function to validate IP address
fn is_valid_ip(ip_str: &str) -> bool {
    ip_str.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_ip() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("10.0.0.1"));
        assert!(!is_valid_ip("999.999.999.999"));
        assert!(!is_valid_ip("not-an-ip"));
    }

    #[test]
    fn test_extract_ip_from_pattern() {
        let pattern = "[ipv4-addr:value = '192.168.1.100']";
        let result = extract_ip_from_pattern(pattern);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }
}