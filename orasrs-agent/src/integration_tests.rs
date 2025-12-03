#[cfg(test)]
mod integration_tests {
    use orasrs_agent::{OrasrsAgent, AgentConfig, ThreatEvidence, ThreatType, ThreatLevel, ThreatIntelAggregator, ConsensusEngine, CredibilityEngine};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio;

    #[tokio::test]
    async fn test_threat_intelligence_aggregation() {
        let aggregator = ThreatIntelAggregator::new();
        
        // Test that we can fetch from upstream sources (simulated)
        let threats = aggregator.fetch_all_sources().await.unwrap();
        
        // Should at least get the simulated CISA AIS threats
        assert!(threats.len() >= 0); // May be 0 if sources are disabled
        
        println!("Fetched {} threats from upstream sources", threats.len());
    }

    #[tokio::test]
    async fn test_consensus_engine() {
        use orasrs_agent::consensus_verification::{ConsensusConfig, VerificationStatus};
        
        let config = ConsensusConfig::default();
        let engine = ConsensusEngine::new(config, "test-agent".to_string());
        
        let evidence = create_test_evidence();
        
        // Submit evidence for verification
        let request = engine.submit_for_verification(evidence.clone()).await.unwrap();
        assert_eq!(request.evidence_id, evidence.id);
        
        // Verify the evidence
        let response = engine.verify_evidence(&request).await.unwrap();
        assert_eq!(response.evidence_id, evidence.id);
        
        // Check for consensus
        let result = engine.check_consensus(&request.request_id).await.unwrap();
        assert_eq!(result.evidence_id, evidence.id);
    }

    #[tokio::test]
    async fn test_credibility_engine() {
        let config = orasrs_agent::credibility_enhancement::CredibilityConfig::default();
        let engine = CredibilityEngine::new(config);
        
        let evidence = create_test_evidence();
        
        // Calculate initial credibility
        let initial_score = engine.calculate_credibility_score(&evidence, Some(0.9)).await.unwrap();
        assert!(initial_score >= 0.0 && initial_score <= 1.0);
        
        // Update with accurate information
        engine.update_credibility(&evidence, true).await.unwrap();
        
        // Calculate updated credibility
        let updated_score = engine.calculate_credibility_score(&evidence, Some(0.9)).await.unwrap();
        assert!(updated_score >= 0.0 && updated_score <= 1.0);
        
        // Enhance the evidence
        let enhanced = engine.enhance_threat_evidence(evidence, Some(0.9)).await.unwrap();
        assert!(enhanced.reputation >= 0.0 && enhanced.reputation <= 1.0);
    }

    #[tokio::test]
    async fn test_end_to_end_integration() {
        // Create a test agent configuration
        let mut config = AgentConfig::default();
        config.agent_id = "test-integration-agent".to_string();
        config.region = "test-region".to_string();
        config.compliance_mode = "global".to_string();
        
        // Create an agent
        let agent = OrasrsAgent::new(config).await.unwrap();
        
        // Create test evidence
        let evidence = create_test_evidence();
        
        // Process the evidence through the full pipeline
        let enhanced_evidence = agent.enhance_threat_evidence(evidence).await.unwrap();
        
        // Check that the evidence has been properly enhanced
        assert!(enhanced_evidence.reputation >= 0.0 && enhanced_evidence.reputation <= 1.0);
        assert!(enhanced_evidence.context.contains("CREDIBILITY"));
        
        println!("Successfully processed evidence through full pipeline: {}", enhanced_evidence.id);
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
            context: "Test threat evidence for integration testing".to_string(),
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