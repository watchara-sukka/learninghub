import socket
import time
import sys

WAZUH_IP = "172.20.0.100"
SYSLOG_PORT = 514

def send_event(msg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    syslog_msg = f"<134>1 {time.strftime('%Y-%m-%dT%H:%M:%SZ')} kali-attacker {msg}"
    sock.sendto(syslog_msg.encode('utf-8'), (WAZUH_IP, SYSLOG_PORT))
    print(f"[💥 Attack Action Executed] Sent syslog: {msg}")
    sock.close()

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 attack_sim.py [scan|modbus-write|touch-decoy|exploit]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "scan":
        send_event("OT_SCAN: Port 502 Modbus scanning detected from 172.20.0.50")
    elif cmd == "modbus-write":
        send_event("Modbus WRITE Command (FC: 06) sent to PLC 172.20.0.20 from 172.20.0.50")
    elif cmd == "touch-decoy":
        send_event("DECOY_PLC_TOUCHED: Unauthorized connection to Decoy PLC (172.20.0.99) from 172.20.0.50")
    elif cmd == "exploit":
        send_event("EXPLOIT_FC90_DETECTED: Critical Exploit Payload (FC: 90) targeting PLC 172.20.0.20 from 172.20.0.50")
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()
