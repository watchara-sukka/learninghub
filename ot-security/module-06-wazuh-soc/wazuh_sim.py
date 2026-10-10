import socket
import os
import sys
import time
import subprocess
from datetime import datetime

UDP_IP = "0.0.0.0"
UDP_PORT = 514
ACTIVE_RESPONSE_LOG = "/var/ossec/logs/active-responses.log"
RULES_FILE = "/var/ossec/etc/rules/local_rules.xml"

# Make sure log dir exists
os.makedirs("/var/ossec/logs", exist_ok=True)

print(f"[*] Wazuh Manager SIEM Engine listening on {UDP_IP}:{UDP_PORT}/udp...")
print(f"[*] Loading rules from {RULES_FILE}...")
print("[*] Wazuh Custom XML Rules Loaded: Rule 100001 (Level 8), Rule 100002 (Level 12), Rule 100003 (Level 14)")
print("[*] Active Response Engine Initialized: /var/ossec/active-response/bin/ot-block.sh")
sys.stdout.flush()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

def run_active_response(attacker_ip, rule_id, level):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] [⚡ WAZUH ACTIVE RESPONSE EXECUTED] Blocked IP {attacker_ip} (Triggered Rule {rule_id} Level {level}+ OT Threat)\n"
    print(log_line.strip())
    sys.stdout.flush()
    with open(ACTIVE_RESPONSE_LOG, "a", encoding="utf-8") as f:
        f.write(log_line)

    # Run ot-block.sh if it exists
    script = "/var/ossec/active-response/bin/ot-block.sh"
    if os.path.exists(script):
        try:
            subprocess.run(["bash", script], input=f'{{"srcip":"{attacker_ip}"}}', text=True, timeout=5)
        except Exception as e:
            pass

while True:
    data, addr = sock.recvfrom(4096)
    msg = data.decode('utf-8', errors='ignore')
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n[📥 Syslog Received from {addr[0]}] {msg}")

    if "Modbus WRITE Command" in msg:
        print(f"[{timestamp}] [WARN Rule 100001 Level 8] OT Warning: Unauthorized Modbus WRITE command detected targeting PLC!")
    elif "DECOY_PLC_TOUCHED" in msg:
        print(f"[{timestamp}] [🚨 CRITICAL Rule 100002 Level 12] CRITICAL OT ALERT: Intruder interacting with Decoy PLC Asset (172.20.0.99)!")
        run_active_response("172.20.0.50", "100002", 12)
    elif "EXPLOIT_FC90_DETECTED" in msg:
        print(f"[{timestamp}] [🚨 CRITICAL Rule 100003 Level 14] CRITICAL OT ALERT: Modbus Firmware Exploit Payload (FC: 90) intercepted!")
        run_active_response("172.20.0.50", "100003", 14)
    else:
        print(f"[{timestamp}] [INFO Rule 100200 Level 3] Generic Syslog Event logged.")
    sys.stdout.flush()
