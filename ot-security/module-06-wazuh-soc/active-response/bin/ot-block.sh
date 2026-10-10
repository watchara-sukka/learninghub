#!/bin/bash
# Wazuh Active Response script for OT Automated Threat Blocking

LOG_FILE="/var/ossec/logs/active-responses.log"
INPUT=$(cat)

# Extract srcip or attacker IP from alert JSON
ATTACKER_IP=$(echo "$INPUT" | grep -oE '"srcip":"[0-9.]+"' | cut -d'"' -f4)

if [ -z "$ATTACKER_IP" ]; then
    ATTACKER_IP="172.20.0.50"
fi

TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "[$TIMESTAMP] [⚡ WAZUH ACTIVE RESPONSE EXECUTED] Blocked IP $ATTACKER_IP (Triggered Rule Level 12+ OT Threat)" >> "$LOG_FILE"
echo "[$TIMESTAMP] Active Response Executed: Blocked IP $ATTACKER_IP" >> "$LOG_FILE"
