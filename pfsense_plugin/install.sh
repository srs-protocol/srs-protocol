#!/bin/sh
# OraSRS v2.0 Threat Intelligence Plugin Installation Script for pfSense

INSTALL_DIR="/usr/local/pkg"
CONFIG_DIR="/usr/local/etc"
SERVICE_NAME="orasrs_plugin"

# Create necessary directories
mkdir -p ${INSTALL_DIR}
mkdir -p ${CONFIG_DIR}

# Copy plugin files
cp orasrs_plugin.php ${INSTALL_DIR}/
chmod 755 ${INSTALL_DIR}/orasrs_plugin.php

# Create default configuration
DEFAULT_CONFIG='{
    "enabled": false,
    "api_endpoint": "https://api.orasrs.example.com",
    "api_key": "",
    "update_interval": 300,
    "block_malicious_ips": true,
    "log_threats": true,
    "consensus_threshold": 0.6,
    "credibility_threshold": 0.7,
    "upstream_sources": {
        "cisa_ais": true,
        "other_source": false
    }
}'

echo "${DEFAULT_CONFIG}" > ${CONFIG_DIR}/orasrs_config.json
chmod 600 ${CONFIG_DIR}/orasrs_config.json

# Create firewall table for blocked IPs
pfctl -t orasrs_blocked -T flush 2>/dev/null
pfctl -t orasrs_blocked -T create 2>/dev/null

# Add required entries to rc.conf for service management
if ! grep -q "orasrs_enable" /etc/rc.conf; then
    echo 'orasrs_enable="YES"' >> /etc/rc.conf
fi

# Create log file
touch /var/log/orasrs.log
chmod 644 /var/log/orasrs.log

# Reload services
service syslog-ng reload

echo "OraSRS v2.0 Threat Intelligence Plugin installed successfully"
echo "Please configure the plugin through pfSense web interface under Services > OraSRS"