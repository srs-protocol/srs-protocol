#[cfg(test)]
mod protocol_tests {
    use orasrs_agent::{
        OrasrsAgent, AgentConfig, ThreatEvidence, ThreatType, ThreatLevel,
        ThreatIntelAggregator, ConsensusEngine, CredibilityEngine,
        consensus_verification::ConsensusConfig,
        credibility_enhancement::CredibilityConfig
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio;

    #[tokio::test]
    async fn test_threat_intel_aggregator_creation() {
        let aggregator = ThreatIntelAggregator::new();
        let sources = aggregator.get_sources_config();
        
        // Should have at least CISA AIS as a source
        assert!(!sources.is_empty());
        
        let cisa_source = sources.iter()
            .find(|s| s.name == "CISA_AIS")
            .expect("CISA AIS source should exist");
            
        assert_eq!(cisa_source.name, "CISA_AIS");
        assert_eq!(cisa_source.enabled, false); // Should be disabled by default
    }

    #[tokio::test]
    async fn test_threat_intel_aggregator_fetch() {
        let aggregator = ThreatIntelAggregator::new();
        
        // Temporarily enable CISA source for testing
        let mut sources = aggregator.get_sources_config();
        for source in &mut sources {
            if source.name == "CISA_AIS" {
                source.enabled = true;
                source.update_interval = 60; // Reduce for testing
            }
        }
        
        // Fetch from simulated sources
        let threats = aggregator.fetch_all_sources().await.unwrap();
        
        // Should have test threats from our simulation
        // Note: This will return empty if sources are disabled in actual implementation
        println!("Fetched {} threats from upstream sources", threats.len());
    }

    #[tokio::test]
    async fn test_consensus_engine_creation() {
        let config = ConsensusConfig::default();
        let engine = ConsensusEngine::new(config, "test-agent".to_string());
        
        assert_eq!(engine.get_config().min_verifiers, 3);
        assert_eq!(engine.get_config().consensus_threshold, 0.6);
    }

    #[tokio::test]
    async fn test_consensus_process_evidence() {
        use orasrs_agent::consensus_verification::VerificationStatus;
        
        let config = ConsensusConfig::default();
        let engine = ConsensusEngine::new(config, "test-agent".to_string());
        
        let evidence = create_test_evidence();
        
        // Submit for verification
        let request = engine.submit_for_verification(evidence.clone()).await.unwrap();
        assert_eq!(request.evidence_id, evidence.id);
        
        // Verify the evidence (this will be from the same agent, so it will auto-verify)
        let response = engine.verify_evidence(&request).await.unwrap();
        assert_eq!(response.evidence_id, evidence.id);
        
        // Check for consensus
        let result = engine.check_consensus(&request.request_id).await.unwrap();
        assert_eq!(result.evidence_id, evidence.id);
        assert!(result.confidence_score >= 0.0);
    }

    #[tokio::test]
    async fn test_credibility_engine_creation() {
        let config = CredibilityConfig::default();
        let engine = CredibilityEngine::new(config);
        
        assert_eq!(engine.config.source_reputation_weight, 0.3);
        assert_eq!(engine.config.high_confidence_threshold, 0.8);
    }

    #[tokio::test]
    async fn test_credibility_calculation() {
        let config = CredibilityConfig::default();
        let engine = CredibilityEngine::new(config);
        
        let evidence = create_test_evidence();
        
        // Calculate credibility with consensus confidence
        let score = engine.calculate_credibility_score(&evidence, Some(0.9)).await.unwrap();
        assert!(score >= 0.0 && score <= 1.0);
        
        // Calculate credibility without consensus confidence
        let score2 = engine.calculate_credibility_score(&evidence, None).await.unwrap();
        assert!(score2 >= 0.0 && score2 <= 1.0);
    }

    #[tokio::test]
    async fn test_agent_creation() {
        let mut config = AgentConfig::default();
        config.agent_id = "test-agent-creation".to_string();
        config.region = "test-region".to_string();
        config.compliance_mode = "global".to_string();
        
        let agent = OrasrsAgent::new(config).await.unwrap();
        
        assert_eq!(agent.config.agent_id, "test-agent-creation");
        assert!(agent.running == false); // Should start not running
    }

    #[tokio::test]
    async fn test_agent_threat_enhancement() {
        let mut config = AgentConfig::default();
        config.agent_id = "test-agent-enhancement".to_string();
        config.region = "test-region".to_string();
        config.compliance_mode = "global".to_string();
        
        let agent = OrasrsAgent::new(config).await.unwrap();
        let evidence = create_test_evidence();
        
        // Test threat enhancement pipeline
        let enhanced = agent.enhance_threat_evidence(evidence).await.unwrap();
        
        // Should have credibility information in context
        assert!(enhanced.context.contains("CREDIBILITY"));
        assert!(enhanced.reputation >= 0.0 && enhanced.reputation <= 1.0);
    }

    #[tokio::test]
    async fn test_consensus_correlation() {
        let config = ConsensusConfig::default();
        let engine = ConsensusEngine::new(config, "test-agent".to_string());
        
        let local_evidence = create_test_evidence_with_ip("192.168.1.100".to_string());
        let upstream_evidence = vec![
            create_test_evidence_with_ip("192.168.1.100".to_string()), // Same IP - should correlate
            create_test_evidence_with_ip("10.0.0.50".to_string()),     // Different IP - should not correlate
        ];
        
        // Process correlation
        let correlations = engine.process_evidence_correlation(&[local_evidence], &upstream_evidence).await.unwrap();
        
        // Should have at least one correlation (the matching IP)
        assert!(!correlations.is_empty());
        
        // The first correlation should have the combined evidence
        let (combined_evidence, consensus_result) = &correlations[0];
        assert!(combined_evidence.context.contains("Combined with upstream"));
        assert!(consensus_result.confidence_score >= 0.0);
    }

    #[test]
    fn test_threat_level_ord() {
        // Test that threat levels are properly ordered
        assert!(ThreatLevel::Info < ThreatLevel::Warning);
        assert!(ThreatLevel::Warning < ThreatLevel::Critical);
        assert!(ThreatLevel::Critical < ThreatLevel::Emergency);
    }

    #[test]
    fn test_threat_type_equality() {
        // Test that threat types work with equality
        assert_eq!(ThreatType::Malware, ThreatType::Malware);
        assert_ne!(ThreatType::Malware, ThreatType::DDoS);
    }

    fn create_test_evidence() -> ThreatEvidence {
        ThreatEvidence {
            id: format!("test-evidence-{}", 
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            source_ip: "192.168.1.100".to_string(),
            target_ip: "10.0.0.1".to_string(),
            threat_type: ThreatType::Malware,
            threat_level: ThreatLevel::Critical,
            context: "Test threat evidence for protocol testing".to_string(),
            evidence_hash: orasrs_agent::crypto::CryptoProvider::blake3_hash(b"test-data"),
            geolocation: "unknown".to_string(),
            network_flow: "TCP".to_string(),
            agent_id: "test-agent".to_string(),
            reputation: 0.8,
            compliance_tag: "global".to_string(),
            region: "test-region".to_string(),
        }
    }

    fn create_test_evidence_with_ip(ip: String) -> ThreatEvidence {
        ThreatEvidence {
            id: format!("test-evidence-{}", 
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            source_ip: ip,
            target_ip: "10.0.0.1".to_string(),
            threat_type: ThreatType::Malware,
            threat_level: ThreatLevel::Critical,
            context: "Test threat evidence for correlation".to_string(),
            evidence_hash: orasrs_agent::crypto::CryptoProvider::blake3_hash(b"test-data"),
            geolocation: "unknown".to_string(),
            network_flow: "TCP".to_string(),
            agent_id: "test-agent".to_string(),
            reputation: 0.8,
            compliance_tag: "global".to_string(),
            region: "test-region".to_string(),
        }
    }
}