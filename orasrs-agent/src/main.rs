use orasrs_agent::{OrasrsAgent, AgentConfig};
use env_logger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger
    env_logger::init();
    
    log::info!("Starting OraSRS Agent v{}", env!("CARGO_PKG_VERSION"));
    
    // Create default agent configuration
    let mut config = AgentConfig::default();
    
    // Enable blocklist export functionality
    config.blocklist_export_enabled = true;
    
    // Create and start the agent
    let mut agent = OrasrsAgent::new(config).await?;
    
    log::info!("OraSRS Agent initialized with ID: {}", agent.config.agent_id);
    
    // Print initial status
    let status = agent.get_status();
    log::info!("Agent status: {:?}", status);
    
    // Start the agent
    match agent.start().await {
        Ok(()) => log::info!("OraSRS Agent started successfully"),
        Err(e) => log::error!("Failed to start agent: {}", e),
    }
    
    // Keep the main thread alive
    tokio::signal::ctrl_c().await?;
    log::info!("Received shutdown signal");
    
    agent.stop()?;
    log::info!("OraSRS Agent stopped");
    
    Ok(())
}