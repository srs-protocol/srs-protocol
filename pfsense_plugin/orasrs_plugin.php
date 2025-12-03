<?php
/*
 * orasrs_plugin.php
 *
 * Part of pfSense Plugins
 *
 * Copyright 2025 OraSRS Protocol
 * MIT License
 *
 * Contains functionality for OraSRS v2.0 Threat Intelligence Integration
 */

require_once("guiconfig.inc");
require_once("functions.inc");
require_once("filter.inc");
require_once("services.inc");

// Define plugin constants
define('ORASRS_PLUGIN_NAME', 'OraSRS v2.0 Threat Intelligence');
define('ORASRS_PLUGIN_VERSION', '2.0.0');
define('ORASRS_CONFIG_PATH', '/usr/local/etc/orasrs_config.json');

// OraSRS pfSense Plugin Class
class OraSRSPlugin {

    private $config_file;
    private $settings;

    public function __construct() {
        $this->config_file = ORASRS_CONFIG_PATH;
        $this->load_settings();
    }

    /**
     * Load plugin settings from file
     */
    private function load_settings() {
        if (file_exists($this->config_file)) {
            $config_content = file_get_contents($this->config_file);
            $this->settings = json_decode($config_content, true) ?: array();
        } else {
            // Default settings
            $this->settings = array(
                'enabled' => false,
                'api_endpoint' => 'https://api.orasrs.example.com',
                'api_key' => '',
                'update_interval' => 300, // 5 minutes
                'block_malicious_ips' => true,
                'log_threats' => true,
                'consensus_threshold' => 0.6,
                'credibility_threshold' => 0.7,
                'upstream_sources' => array(
                    'cisa_ais' => true,
                    'other_source' => false
                )
            );
            $this->save_settings();
        }
    }

    /**
     * Save plugin settings to file
     */
    public function save_settings() {
        file_put_contents($this->config_file, json_encode($this->settings, JSON_PRETTY_PRINT));
        // Signal pfSense to reload configuration
        system("killall -HUP syslogd");
    }

    /**
     * Get current plugin settings
     */
    public function get_settings() {
        return $this->settings;
    }

    /**
     * Update plugin settings
     */
    public function update_settings($new_settings) {
        $this->settings = array_merge($this->settings, $new_settings);
        $this->save_settings();
    }

    /**
     * Fetch threat intelligence from OraSRS network
     */
    public function fetch_threat_intelligence() {
        if (!$this->settings['enabled']) {
            return array('error' => 'Plugin not enabled');
        }

        $api_endpoint = rtrim($this->settings['api_endpoint'], '/') . '/api/v2.0/threats';
        $api_key = $this->settings['api_key'];

        $context = stream_context_create(array(
            'http' => array(
                'method' => 'GET',
                'header' => array(
                    'Authorization: Bearer ' . $api_key,
                    'Content-Type: application/json',
                    'User-Agent: pfSense-OraSRS-Plugin/' . ORASRS_PLUGIN_VERSION
                ),
                'timeout' => 30
            )
        ));

        $response = @file_get_contents($api_endpoint, false, $context);

        if ($response === false) {
            return array('error' => 'Failed to connect to OraSRS API');
        }

        $data = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return array('error' => 'Invalid JSON response from OraSRS API');
        }

        return $data;
    }

    /**
     * Fetch upstream threat intelligence (e.g., CISA AIS)
     */
    public function fetch_upstream_intelligence() {
        if (!$this->settings['enabled']) {
            return array('error' => 'Plugin not enabled');
        }

        $api_endpoint = rtrim($this->settings['api_endpoint'], '/') . '/api/v2.0/threats/upstream';
        $api_key = $this->settings['api_key'];

        $context = stream_context_create(array(
            'http' => array(
                'method' => 'GET',
                'header' => array(
                    'Authorization: Bearer ' . $api_key,
                    'Content-Type: application/json'
                ),
                'timeout' => 30
            )
        ));

        $response = @file_get_contents($api_endpoint, false, $context);

        if ($response === false) {
            return array('error' => 'Failed to fetch upstream intelligence');
        }

        $data = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return array('error' => 'Invalid JSON response from upstream source');
        }

        return $data;
    }

    /**
     * Add malicious IPs to pfSense block list
     */
    public function add_to_blocklist($ip_list) {
        $blocked_ips = array();
        
        foreach ($ip_list as $ip_entry) {
            $ip = $ip_entry['ip'] ?? $ip_entry;
            $credibility = $ip_entry['credibility_score'] ?? 1.0;
            
            // Only block if credibility is above threshold
            if ($credibility >= $this->settings['credibility_threshold']) {
                // Add to pfSense firewall table
                $result = mwexec("/sbin/pfctl -t orasrs_blocked -T add {$ip} 2>/dev/null", true);
                
                if ($result === 0) {
                    $blocked_ips[] = $ip;
                    if ($this->settings['log_threats']) {
                        syslog(LOG_WARNING, "OraSRS: Blocked malicious IP {$ip} (Credibility: {$credibility})");
                    }
                }
            }
        }
        
        return $blocked_ips;
    }

    /**
     * Remove IPs from blocklist
     */
    public function remove_from_blocklist($ip_list) {
        foreach ($ip_list as $ip) {
            mwexec("/sbin/pfctl -t orasrs_blocked -T delete {$ip} 2>/dev/null", true);
        }
    }

    /**
     * Create firewall table for OraSRS blocked IPs
     */
    public function create_firewall_table() {
        mwexec("/sbin/pfctl -t orasrs_blocked -T flush 2>/dev/null", true);
        mwexec("/sbin/pfctl -t orasrs_blocked -T create 2>/dev/null", true);
    }

    /**
     * Apply firewall rules to block OraSRS flagged IPs
     */
    public function apply_firewall_rules() {
        // Create the table if it doesn't exist
        $this->create_firewall_table();
        
        // Add rule to block traffic from OraSRS flagged IPs
        $rule_exists = shell_exec("/sbin/pfctl -sr 2>/dev/null | grep 'orasrs_blocked'");
        
        if (empty($rule_exists)) {
            // Add block rule to pf.conf
            $pfconf = file_get_contents("/tmp/pf.conf");
            if ($pfconf !== false) {
                // Add our rule before the final block
                $new_rule = "block in quick from <orasrs_blocked> to any\n";
                $pfconf = $new_rule . $pfconf;
                file_put_contents("/tmp/pf.conf", $pfconf);
                
                // Reload pf rules
                filter_configure();
            }
        }
    }

    /**
     * Process threat intelligence and update firewall
     */
    public function process_threat_intelligence() {
        if (!$this->settings['enabled']) {
            return false;
        }

        // Fetch threat intelligence from OraSRS
        $threat_data = $this->fetch_threat_intelligence();
        
        if (isset($threat_data['error'])) {
            syslog(LOG_ERR, "OraSRS: Error fetching threat intelligence - " . $threat_data['error']);
            return false;
        }

        // Extract IPs with high credibility scores
        $high_risk_ips = array();
        foreach ($threat_data['threats'] ?? array() as $threat) {
            if (isset($threat['source_ip']) && 
                isset($threat['credibility_score']) && 
                $threat['credibility_score'] >= $this->settings['credibility_threshold']) {
                
                $high_risk_ips[] = array(
                    'ip' => $threat['source_ip'],
                    'credibility_score' => $threat['credibility_score']
                );
            }
        }

        // Add high-risk IPs to blocklist if enabled
        if ($this->settings['block_malicious_ips'] && !empty($high_risk_ips)) {
            $blocked = $this->add_to_blocklist($high_risk_ips);
            if (!empty($blocked)) {
                syslog(LOG_INFO, "OraSRS: Added " . count($blocked) . " IPs to blocklist");
            }
        }

        // Also process upstream intelligence
        if ($this->settings['upstream_sources']['cisa_ais']) {
            $upstream_data = $this->fetch_upstream_intelligence();
            
            if (!isset($upstream_data['error'])) {
                $upstream_ips = array();
                foreach ($upstream_data['upstream_threats'] ?? array() as $threat) {
                    if (isset($threat['source_ip'])) {
                        $upstream_ips[] = array(
                            'ip' => $threat['source_ip'],
                            'credibility_score' => $threat['confidence'] ?? 0.9  // Upstream sources typically have high confidence
                        );
                    }
                }
                
                if ($this->settings['block_malicious_ips'] && !empty($upstream_ips)) {
                    $blocked = $this->add_to_blocklist($upstream_ips);
                    if (!empty($blocked)) {
                        syslog(LOG_INFO, "OraSRS: Added " . count($blocked) . " upstream IPs to blocklist");
                    }
                }
            }
        }

        return true;
    }

    /**
     * Schedule periodic updates
     */
    public function schedule_updates() {
        // Add cron job for periodic updates if not already present
        $cron_job = "*/" . $this->settings['update_interval'] . " * * * * /usr/local/bin/php /usr/local/pkg/orasrs_plugin.php --update";
        
        // Read current crontab
        $cron_content = file_get_contents("/etc/crontab") ?: '';
        
        // Check if our job is already present
        if (strpos($cron_content, 'orasrs_plugin.php --update') === false) {
            // Add our job to crontab
            $cron_content .= "\n{$cron_job} # OraSRS Threat Intelligence Update\n";
            file_put_contents("/etc/crontab", $cron_content);
            
            // Reload cron
            system("service cron reload");
        }
    }

    /**
     * Run periodic update
     */
    public function run_periodic_update() {
        $this->process_threat_intelligence();
    }
}

// Handle command line execution for cron jobs
if (php_sapi_name() === 'cli' && isset($argv) && in_array('--update', $argv)) {
    require_once('/etc/inc/config.inc');
    require_once('/etc/inc/functions.inc');
    
    $plugin = new OraSRSPlugin();
    $plugin->run_periodic_update();
    exit(0);
}

?>