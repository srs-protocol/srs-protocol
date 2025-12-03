use orasrs_agent::{OrasrsAgent, AgentConfig, ThreatEvidence, ThreatType, ThreatLevel, ThreatIntelAggregator, ConsensusEngine, CredibilityEngine};
use orasrs_agent::consensus_verification::{ConsensusConfig, ConsensusResult};
use orasrs_agent::credibility_enhancement::CredibilityConfig;
use std::time::{SystemTime, UNIX_EPOCH};

/// 示例：展示如何使用OraSRS v2.0的威胁情报集成和共识验证功能
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("OraSRS v2.0 Threat Intelligence Integration Example");
    println!("===============================================");
    
    // 1. 创建代理配置
    let mut config = AgentConfig::default();
    config.agent_id = "example-agent-001".to_string();
    config.region = "global".to_string();
    config.compliance_mode = "global".to_string();
    
    // 2. 创建OraSRS代理实例
    let agent = OrasrsAgent::new(config).await?;
    println!("✓ Created OraSRS Agent instance");
    
    // 3. 演示CISA AIS威胁情报获取
    let threats = agent.threat_intel_aggregator.fetch_all_sources().await?;
    println!("✓ Fetched {} threats from upstream sources (simulated)", threats.len());
    
    // 4. 创建本地检测到的威胁证据
    let local_evidence = ThreatEvidence {
        id: format!("local-evidence-{}", 
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        source_ip: "203.0.113.42".to_string(),  // Example IP from RFC 5737
        target_ip: "198.51.100.23".to_string(),  // Example IP from RFC 5737
        threat_type: ThreatType::SuspiciousConnection,
        threat_level: ThreatLevel::Warning,
        context: "Suspicious connection pattern detected by local analyzer".to_string(),
        evidence_hash: orasrs_agent::crypto::CryptoProvider::blake3_hash(b"local-network-flow-data"),
        geolocation: "unknown".to_string(),
        network_flow: "TCP SYN flood pattern".to_string(),
        agent_id: "example-agent-001".to_string(),
        reputation: 0.85,
        compliance_tag: "global".to_string(),
        region: "global".to_string(),
    };
    
    println!("✓ Created local threat evidence: {}", local_evidence.id);
    
    // 5. 获取上游威胁情报（模拟CISA AIS数据）
    let upstream_threats = agent.threat_intel_aggregator.fetch_all_sources().await?;
    println!("✓ Retrieved {} upstream threats", upstream_threats.len());
    
    // 6. 执行本地检测与上游数据的共识验证
    let correlation_results = agent.consensus_engine
        .process_evidence_correlation(&[local_evidence.clone()], &upstream_threats)
        .await?;
    
    println!("✓ Completed correlation and consensus verification");
    
    // 7. 增强威胁证据可信度
    let enhanced_evidence = agent.enhance_threat_evidence(local_evidence).await?;
    println!("✓ Enhanced threat evidence with credibility score: {:.2}", enhanced_evidence.reputation);
    
    // 8. 显示结果
    if !correlation_results.is_empty() {
        let (_, consensus_result) = &correlation_results[0];
        print_consensus_result(consensus_result);
        
        println!("\nEnhanced Threat Evidence Details:");
        println!("  ID: {}", enhanced_evidence.id);
        println!("  Source IP: {}", enhanced_evidence.source_ip);
        println!("  Threat Type: {:?}", enhanced_evidence.threat_type);
        println!("  Original Level: {:?}", enhanced_evidence.threat_level);
        println!("  Credibility Score: {:.2}", enhanced_evidence.reputation);
        println!("  Context: {}", enhanced_evidence.context);
    } else {
        println!("No correlations found between local and upstream threats");
    }
    
    // 9. 演示提交增强后的威胁证据
    agent.submit_threat_evidence(enhanced_evidence).await?;
    println!("✓ Submitted enhanced threat evidence to P2P network");
    
    println!("\n✓ All integration steps completed successfully!");
    println!("The OraSRS v2.0 agent successfully integrated:");
    println!("  - CISA AIS upstream threat intelligence");
    println!("  - Local threat detection");
    println!("  - Consensus verification between local and upstream data");
    println!("  - Credibility enhancement based on verification results");
    
    Ok(())
}

/// 打印共识验证结果
fn print_consensus_result(result: &ConsensusResult) {
    println!("\nConsensus Verification Results:");
    println!("  Evidence ID: {}", result.evidence_id);
    println!("  Consensus Verdict: {}", if result.consensus_verdict { "VERIFIED" } else { "DISPUTED" });
    println!("  Confidence Score: {:.2}", result.confidence_score);
    println!("  Consensus Percentage: {:.2}%", result.consensus_percentage * 100.0);
    println!("  Verified by {} agents", result.verified_by.len());
    println!("  Disputed by {} agents", result.disputed_by.len());
}
