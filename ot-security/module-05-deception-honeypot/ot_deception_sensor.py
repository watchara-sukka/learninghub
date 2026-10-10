import socket
import threading
import sys
import time
from datetime import datetime

DECOY_IP = "172.20.0.99"
LISTEN_PORT = 5022 # พอร์ตดักฟังการแจ้งเตือน
LOG_FILE = "deception_alerts.log"

def log_alert(attacker_ip, port, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_msg = f"[{timestamp}] [🚨 CRITICAL DECEPTION ALERT] Intruder detected! Attacker IP: {attacker_ip} targeted Decoy Asset ({DECOY_IP}:{port}) - Details: {details}"
    print("\n" + "="*90)
    print(alert_msg)
    print("🎯 Analysis: Zero False Positive! No legitimate system should ever touch the Decoy PLC.")
    print("="*90 + "\n")

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(alert_msg + "\n")

def simulate_deception_trap_listener():
    # สร้าง Socket จำลองการรับ Trap สัญญาณจาก Decoy Asset
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(5)
    print(f"[*] Deception Security Monitor is running on 172.20.0.100:{LISTEN_PORT}...")
    print(f"[*] Watching Decoy Asset ({DECOY_IP}). Ready for High-Fidelity Alerting...")

    while True:
        client, addr = server.accept()
        data = client.recv(1024).decode('utf-8', errors='ignore')
        if data:
            log_alert(addr[0], 502, data)
        client.close()

if __name__ == "__main__":
    simulate_deception_trap_listener()
