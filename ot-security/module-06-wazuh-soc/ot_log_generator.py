import socket
import time
import sys

WAZUH_IP = "172.20.0.100"
SYSLOG_PORT = 514

def send_syslog(message):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # ฟอร์แมต Syslog RFC3164
        syslog_msg = f"<134>1 {time.strftime('%Y-%m-%dT%H:%M:%SZ')} OT-SECURITY-GW {message}"
        sock.sendto(syslog_msg.encode('utf-8'), (WAZUH_IP, SYSLOG_PORT))
        print(f"[📡 Syslog Sent -> Wazuh] {message}")
        sock.close()
    except Exception as e:
        print(f"[-] Error sending syslog: {e}")

def main():
    print("[*] OT Security Log Collector Engine running... Connected to Wazuh SIEM.")
    sys.stdout.flush()
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
