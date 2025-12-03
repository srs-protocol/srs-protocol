use crate::{ThreatEvidence, ThreatLevel, ThreatType, error::{AgentError, Result}};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Write, BufWriter};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Blocklist exporter to convert threat evidence to blocklist.txt format
pub struct BlocklistExporter {
    blocklist_file: String,
    threat_cache: HashSet<String>,  // Cache to avoid duplicate IPs
    min_threat_level: ThreatLevel,  // Minimum threat level to include in blocklist
    export_interval: u64,           // Export interval in seconds
}

impl BlocklistExporter {
    /// Create a new blocklist exporter
    pub fn new(blocklist_file: String, min_threat_level: ThreatLevel, export_interval: u64) -> Self {
        Self {
            blocklist_file,
            threat_cache: HashSet::new(),
            min_threat_level,
            export_interval,
        }
    }

    /// Start the blocklist export service
    pub async fn start_export(&mut self, mut evidence_queue: mpsc::UnboundedReceiver<ThreatEvidence>) -> Result<()> {
        log::info!("Starting blocklist export service...");
        
        // Initialize the blocklist file
        self.initialize_blocklist_file()?;
        
        while let Some(evidence) = evidence_queue.recv().await {
            // Check if threat level is high enough for blocklist
            if evidence.threat_level as u8 >= self.min_threat_level as u8 {
                // Add source IP to blocklist if not already present
                if self.threat_cache.insert(evidence.source_ip.clone()) {
                    self.add_to_blocklist(&evidence.source_ip, &evidence)?;
                }
            }
        }
        
        Ok(())
    }

    /// Initialize the blocklist file with header
    fn initialize_blocklist_file(&self) -> Result<()> {
        let mut file = File::create(&self.blocklist_file)?;
        
        // Write header information
        writeln!(file, "# OraSRS Agent Blocklist")?;
        writeln!(file, "# Generated: {}", chrono::Utc::now().to_rfc3339())?;
        writeln!(file, "# Contains IP addresses detected as threats by OraSRS Agent")?;
        writeln!(file, "# Minimum threat level: {:?}", self.min_threat_level)?;
        writeln!(file, "")?;
        
        Ok(())
    }

    /// Add an IP to the blocklist file
    fn add_to_blocklist(&mut self, ip: &str, evidence: &ThreatEvidence) -> Result<()> {
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.blocklist_file)?;
        
        let mut writer = BufWriter::new(file);
        
        // Write the IP with comment about the threat
        writeln!(
            writer, 
            "{} # {} - {} - {} - Agent: {}", 
            ip,
            self.threat_level_to_string(evidence.threat_level),
            self.threat_type_to_string(&evidence.threat_type),
            evidence.context,
            evidence.agent_id
        )?;
        
        writer.flush()?;
        
        log::info!("Added {} to blocklist: {} - {}", ip, self.threat_type_to_string(&evidence.threat_type), evidence.context);
        
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
        threat_type.as_ref()
    }

    /// Get current reputation
    pub fn get_reputation(&self) -> f64 {
        0.95  // Placeholder
    }
}

/// Function to create and start a blocklist exporter
pub async fn start_blocklist_exporter(
    blocklist_file: String,
    min_threat_level: ThreatLevel,
    export_interval: u64,
    evidence_queue: mpsc::UnboundedReceiver<ThreatEvidence>,
) -> Result<()> {
    let mut exporter = BlocklistExporter::new(blocklist_file, min_threat_level, export_interval);
    exporter.start_export(evidence_queue).await
}