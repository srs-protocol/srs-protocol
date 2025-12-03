use crate::{
    AgentConfig, 
    AgentStatus, 
    ThreatEvidence, 
    monitor::AgentMonitor, 
    analyzer::ThreatDetector, 
    reporter::ThreatReporter, 
    p2p::P2pClient, 
    compliance::ComplianceEngine,
    blocklist_exporter::{BlocklistExporter, start_blocklist_exporter},
    threat_intel_upstream::ThreatIntelAggregator,
    consensus_verification::{ConsensusEngine, ConsensusConfig},
    credibility_enhancement::{CredibilityEngine, CredibilityConfig},
    error::{AgentError, Result},
    ThreatLevel,
};
use tokio::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::time::interval;

/// Main OraSRS Agent implementation
pub struct OrasrsAgent {
    pub config: AgentConfig,
    pub monitor: AgentMonitor,
    pub analyzer: ThreatDetector,
    pub reporter: ThreatReporter,
    pub p2p_client: P2pClient,
    pub compliance_engine: ComplianceEngine,
    pub threat_intel_aggregator: ThreatIntelAggregator,
    pub consensus_engine: ConsensusEngine,
    pub credibility_engine: CredibilityEngine,
    pub status: AgentStatus,
    pub running: bool,
    blocklist_receiver: Option<tokio::sync::mpsc::UnboundedReceiver<ThreatEvidence>>,
}

impl OrasrsAgent {
    /// Create a new OraSRS Agent instance
    pub async fn new(config: AgentConfig) -> Result<Self> {
        // Create the main threat sender/receiver
        let (threat_sender_main, threat_receiver_main) = mpsc::unbounded_channel::<ThreatEvidence>();
        
        // Create a thread to duplicate threat evidence to multiple receivers
        let (reporter_sender, threat_receiver_reporter) = mpsc::unbounded_channel::<ThreatEvidence>();
        let (blocklist_sender_internal, blocklist_receiver_for_exporter) = mpsc::unbounded_channel::<ThreatEvidence>();
        
        // Create a forwarding task to duplicate threat evidence
        let _forwarder_task = tokio::spawn({
            let mut receiver = threat_receiver_main;
            let reporter_tx = reporter_sender;
            let blocklist_tx = blocklist_sender_internal;
            let blocklist_enabled = config.blocklist_export_enabled;
            
            async move {
                while let Some(evidence) = receiver.recv().await {
                    // Send to reporter
                    let _ = reporter_tx.send(evidence.clone());
                    
                    // Send to blocklist exporter if enabled
                    if blocklist_enabled {
                        let _ = blocklist_tx.send(evidence);
                    }
                }
            }
        });
        
        // Initialize compliance engine first
        let mut compliance_engine = ComplianceEngine::new(&config);
        compliance_engine.init_compliance()?;
        
        // Validate config compliance
        compliance_engine.validate_config_compliance(&config)?;
        
        // Initialize P2P client
        let mut p2p_client = P2pClient::new(config.clone())?;
        
        // Initialize threat intelligence aggregator
        let threat_intel_aggregator = ThreatIntelAggregator::new();
        
        // Initialize consensus engine
        let consensus_config = ConsensusConfig::default();
        let consensus_engine = ConsensusEngine::new(consensus_config, config.agent_id.clone());
        
        // Initialize credibility engine
        let credibility_config = CredibilityConfig::default();
        let credibility_engine = CredibilityEngine::new(credibility_config);
        
        // Initialize components
        let monitor = AgentMonitor::new(
            config.enabled_modules.netflow,
            config.enabled_modules.syscall,
            config.enabled_modules.tls_inspect,
            config.enabled_modules.geo_fence,
            threat_sender_main,  // Send threats to the duplicator
        );
        
        let analyzer = ThreatDetector::new();
        
        // Create blocklist sender for the reporter to use (we'll pass None since we handle duplication separately)
        let reporter = ThreatReporter::new(
            config.agent_id.clone(),
            config.clone(),
            threat_receiver_reporter,  // The reporter gets its own dedicated receiver
            None,  // We handle blocklist duplication separately
        );
        
        // Get current time for uptime calculation
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let status = AgentStatus {
            agent_id: config.agent_id.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: start_time,
            threat_count: 0,
            reputation: 1.0,
            memory_usage: 0, // Will be updated by monitoring
            cpu_usage: 0.0,  // Will be updated by monitoring
            network_usage: 0, // Will be updated by monitoring
            last_threat_report: None,
            p2p_connected: false,
            compliance_mode: config.compliance_mode.clone(),
        };
        
        let mut agent = Self {
            config,
            monitor,
            analyzer,
            reporter,
            p2p_client,
            compliance_engine,
            threat_intel_aggregator,
            consensus_engine,
            credibility_engine,
            status,
            running: false,
            blocklist_receiver: if config.blocklist_export_enabled {
                Some(blocklist_receiver_for_exporter)
            } else {
                None
            },
        };
        
        // Connect to P2P network
        agent.p2p_client.connect_bootstrap().await?;
        agent.status.p2p_connected = agent.p2p_client.connected;
        
        // Subscribe to threat intelligence
        agent.p2p_client.subscribe_threat_intel()?;
        
        Ok(agent)
    }
    
    /// Start the agent
    pub async fn start(&mut self) -> Result<()> {
        log::info!("Starting OraSRS Agent v{}...", env!("CARGO_PKG_VERSION"));
        
        self.running = true;
        
        // Start monitor
        self.monitor.start_monitoring().await?;
        log::info!("Monitor started");
        
        // Start reporter
        let reporter_handle = tokio::spawn({
            let mut reporter = std::mem::take(&mut self.reporter);
            async move {
                if let Err(e) = reporter.start_reporting().await {
                    log::error!("Reporter error: {}", e);
                }
            }
        });
        log::info!("Reporter started");
        
        // Start blocklist exporter if enabled in config
        let blocklist_handle = if self.config.blocklist_export_enabled {
            let blocklist_file = self.config.blocklist_file.clone().unwrap_or_else(|| "./blocklist.txt".to_string());
            let min_threat_level = self.config.blocklist_min_threat_level.unwrap_or(ThreatLevel::Warning);
            let export_interval = self.config.blocklist_export_interval.unwrap_or(300); // 5 minutes
            
            // Take the blocklist receiver from the agent
            if let Some(blocklist_receiver) = self.blocklist_receiver.take() {
                Some(tokio::spawn({
                    async move {
                        if let Err(e) = start_blocklist_exporter(
                            blocklist_file,
                            min_threat_level,
                            export_interval,
                            blocklist_receiver
                        ).await {
                            log::error!("Blocklist exporter error: {}", e);
                        }
                    }
                }))
            } else {
                log::warn!("Blocklist receiver not available");
                None
            }
        } else {
            None
        };
        
        if self.config.blocklist_export_enabled {
            log::info!("Blocklist exporter started");
        }
        
        // Start threat intelligence aggregation
        self.start_threat_intel_aggregation().await?;
        log::info!("Threat intelligence aggregation started");
        
        // Start status monitoring loop
        let status_handle = tokio::spawn({
            let mut interval = interval(Duration::from_secs(self.config.update_interval));
            let agent_id = self.config.agent_id.clone();
            let p2p_client = self.p2p_client.clone();
            let mut status = self.status.clone();
            let running = &self.running;
            
            async move {
                loop {
                    interval.tick().await;
                    
                    if !running {
                        break;
                    }
                    
                    // Update status
                    status.uptime = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() - status.uptime;
                    
                    status.reputation = 0.95; // Placeholder - would come from reporter
                    status.p2p_connected = p2p_client.connected;
                    
                    log::debug!("Agent status updated: {:?}", status);
                }
            }
        });
        log::info!("Status monitoring started");
        
        // Keep the agent running
        if let Some(handle) = blocklist_handle {
            tokio::try_join!(
                async { Ok(reporter_handle.await?) },
                async { handle.await.map_err(|e| AgentError::InternalError(e.to_string())) },
                async { 
                    status_handle.await.map_err(|e| AgentError::InternalError(e.to_string())) 
                }
            )?;
        } else {
            tokio::try_join!(
                async { Ok(reporter_handle.await?) },
                async { 
                    status_handle.await.map_err(|e| AgentError::InternalError(e.to_string())) 
                }
            )?;
        }
        
        Ok(())
    }
    
    /// Stop the agent
    pub fn stop(&mut self) -> Result<()> {
        log::info!("Stopping OraSRS Agent...");
        self.running = false;
        Ok(())
    }
    
    /// Get current agent status
    pub fn get_status(&self) -> AgentStatus {
        AgentStatus {
            agent_id: self.config.agent_id.clone(),
            version: self.status.version.clone(),
            uptime: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() - self.status.uptime,
            threat_count: self.status.threat_count,
            reputation: self.reporter.get_reputation(),
            memory_usage: self.status.memory_usage,
            cpu_usage: self.status.cpu_usage,
            network_usage: self.status.network_usage,
            last_threat_report: self.status.last_threat_report,
            p2p_connected: self.p2p_client.connected,
            compliance_mode: self.status.compliance_mode.clone(),
        }
    }
    
    /// Update agent configuration
    pub fn update_config(&mut self, new_config: AgentConfig) -> Result<()> {
        // Validate new config compliance
        self.compliance_engine.validate_config_compliance(&new_config)?;
        
        // Update config
        self.config = new_config;
        
        // Update status
        self.status.compliance_mode = self.config.compliance_mode.clone();
        
        log::info!("Agent configuration updated");
        Ok(())
    }
    
    /// Submit a threat evidence manually
    pub async fn submit_threat_evidence(&self, mut evidence: ThreatEvidence) -> Result<()> {
        // Set agent-specific fields
        evidence.agent_id = self.config.agent_id.clone();
        evidence.reputation = self.reporter.get_reputation();
        evidence.compliance_tag = self.config.compliance_mode.clone();
        evidence.region = self.config.region.clone();
        
        // Process evidence according to compliance settings
        let processed_evidence = self.compliance_engine
            .process_evidence(evidence, &self.config)?;
        
        // Enhance with credibility and consensus verification
        let enhanced_evidence = self.enhance_threat_evidence(processed_evidence).await?;
        
        // Publish to P2P network
        self.p2p_client.publish_threat_evidence(&enhanced_evidence).await?;
        
        // Update status
        self.update_threat_count();
        
        Ok(())
    }
    
    /// Update threat count in status
    fn update_threat_count(&mut self) {
        self.status.threat_count += 1;
        self.status.last_threat_report = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        );
    }
    
    /// Enhance threat evidence with credibility and consensus verification
    async fn enhance_threat_evidence(&self, evidence: ThreatEvidence) -> Result<ThreatEvidence> {
        log::debug!("Enhancing threat evidence: {}", evidence.id);
        
        // First, check if there are any upstream threats that correlate with this evidence
        let upstream_threats = self.threat_intel_aggregator.fetch_all_sources().await.unwrap_or_default();
        
        // Perform correlation between local evidence and upstream threats
        let correlation_results = self.consensus_engine
            .process_evidence_correlation(&[evidence.clone()], &upstream_threats)
            .await?;
        
        // Extract consensus confidence from correlation results
        let consensus_confidence = if !correlation_results.is_empty() {
            Some(correlation_results[0].1.confidence_score)
        } else {
            None
        };
        
        // Enhance with credibility engine
        let enhanced_evidence = self.credibility_engine
            .enhance_threat_evidence(evidence, consensus_confidence)
            .await?;
        
        // Update credibility based on the correlation results
        if !correlation_results.is_empty() {
            let (_, consensus_result) = &correlation_results[0];
            // Update credibility based on consensus result
            self.credibility_engine.update_credibility(
                &enhanced_evidence, 
                consensus_result.consensus_verdict
            ).await?;
        }
        
        log::info!("Enhanced threat evidence {} with credibility score: {:.2}", 
                  enhanced_evidence.id, enhanced_evidence.reputation);
        
        Ok(enhanced_evidence)
    }
    
    /// Start the threat intelligence aggregation service
    pub async fn start_threat_intel_aggregation(&self) -> Result<()> {
        log::info!("Starting threat intelligence aggregation service...");
        
        // Spawn a background task to periodically fetch upstream threat intelligence
        tokio::spawn({
            let aggregator = self.threat_intel_aggregator.clone();
            async move {
                loop {
                    match aggregator.fetch_all_sources().await {
                        Ok(threats) => {
                            log::info!("Fetched {} upstream threats", threats.len());
                            // Could process these threats further if needed
                        }
                        Err(e) => {
                            log::error!("Error fetching upstream threat intelligence: {}", e);
                        }
                    }
                    
                    // Wait for the configured interval before next fetch
                    tokio::time::sleep(tokio::time::Duration::from_secs(300)).await; // 5 minutes
                }
            }
        });
        
        Ok(())
    }
}

// Note: OrasrsAgent does not implement Clone because it contains non-cloneable elements like receivers.
// Instead, components that need access to the agent should receive references or use Arc<Mutex<OrasrsAgent>> if needed.

impl ComplianceEngine {
    /// Process evidence according to compliance settings
    pub fn process_evidence(&self, mut evidence: ThreatEvidence, config: &AgentConfig) -> Result<ThreatEvidence> {
        // Apply privacy settings based on privacy level
        match config.privacy_level {
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
}