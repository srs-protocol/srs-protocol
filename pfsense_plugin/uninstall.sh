#!/bin/sh
# OraSRS v2.0 Threat Intelligence Plugin Uninstallation Script for pfSense

INSTALL_DIR="/usr/local/pkg"
CONFIG_DIR="/usr/local/etc"
SERVICE_NAME="orasrs_plugin"

# Remove plugin files
rm -f ${INSTALL_DIR}/orasrs_plugin.php
rm -f ${CONFIG_DIR}/orasrs_config.json

# Remove firewall table
pfctl -t orasrs_blocked -T flush 2>/dev/null
pfctl -t orasrs_blocked -T delete 2>/dev/null

# Remove log file
rm -f /var/log/orasrs.log

# Remove service entry from rc.conf
sed -i '' '/orasrs_enable/d' /etc/rc.conf

# Remove cron job if it exists
sed -i '' '/orasrs_plugin.php/d' /etc/crontab

echo "OraSRS v2.0 Threat Intelligence Plugin uninstalled successfully"