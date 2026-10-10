import socket
import threading
import sys
import datetime

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 9022
PLC_IP = "172.22.0.20"
PLC_PORT = 502

# Credential Vault จำลอง (ชี้แจงสิทธิ์ Vendor)
VALID_VENDOR_TOKEN = "VENDOR-SECRET-KEY-99"

# รายการคำสั่งอันตรายที่ห้าม Vendor สั่งงาน (Command Blacklist)
DANGEROUS_COMMANDS = ["reboot_plc", "override_safety", "stop_production", "clear_logs"]

def log_audit(vendor_ip, action, status, details=""):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] [VENDOR: {vendor_ip}] ACTION: {action} | STATUS: {status} | DETAILS: {details}\n"
    print(log_line.strip())
    with open("session_audit.log", "a", encoding="utf-8") as f:
        f.write(log_line)

def handle_vendor_session(client_sock, addr):
    vendor_ip = addr[0]
    log_audit(vendor_ip, "SESSION_CONNECT", "INFO", "Vendor connected to PAM Gateway")

    try:
        client_sock.sendall(b"=== OT-PAM GATEWAY ACCESS ===\nPlease enter Vendor Session Token: ")
        token = client_sock.recv(1024).decode('utf-8', errors='ignore').strip()

        if token != VALID_VENDOR_TOKEN:
            log_audit(vendor_ip, "AUTHENTICATION", "DENIED", "Invalid Vendor Token provided")
            client_sock.sendall("\n[🚫 PAM ERROR] Authentication Failed: Invalid Token. Session Terminated.\n".encode('utf-8'))
            client_sock.close()
            return

        log_audit(vendor_ip, "AUTHENTICATION", "SUCCESS", "Vendor identity verified. Vault credential injected.")
        client_sock.sendall("\n[🟢 PAM AUTH OK] Authenticated successfully.\nConnected to PLC-SCADA via Secure Vault Proxy.\nCommands available: read_status, calibrate_sensor, reboot_plc, override_safety\nEnter command (or 'exit'): ".encode('utf-8'))

        while True:
            cmd = client_sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if not cmd or cmd.lower() == 'exit':
                log_audit(vendor_ip, "SESSION_DISCONNECT", "INFO", "Vendor closed session")
                break

            # [Real-time Command Filtering]
            if cmd in DANGEROUS_COMMANDS:
                log_audit(vendor_ip, f"COMMAND: {cmd}", "BLOCKED", "Triggered PAM Security Rules (Dangerous Command)")
                client_sock.sendall(f"\n[🚫 PAM SECURITY BLOCK] Command '{cmd}' is BLACKLISTED for Vendor accounts!\nEnter command: ".encode('utf-8'))
            else:
                # ส่งคำสั่งจำลองต่อไปยัง PLC ปลายทาง
                log_audit(vendor_ip, f"COMMAND: {cmd}", "EXECUTED", "Forwarded through secure proxy to PLC")
                client_sock.sendall(f"\n[🟢 SUCCESS] Command '{cmd}' executed on PLC-SCADA successfully.\nEnter command: ".encode('utf-8'))

    except Exception as e:
        log_audit(vendor_ip, "SESSION_ERROR", "ERROR", str(e))
    finally:
        client_sock.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_IP, LISTEN_PORT))
    server.listen(5)
    print(f"[*] OT-PAM Gateway listening on {LISTEN_IP}:{LISTEN_PORT}...")
    while True:
        client_sock, addr = server.accept()
        threading.Thread(target=handle_vendor_session, args=(client_sock, addr)).start()

if __name__ == "__main__":
    main()
