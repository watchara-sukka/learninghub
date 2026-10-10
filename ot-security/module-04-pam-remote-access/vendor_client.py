import socket
import sys
import time

PAM_IP = "172.21.0.10"
PAM_PORT = 9022

def run_vendor_client(token, command_to_run):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((PAM_IP, PAM_PORT))

        # รับข้อความต้อนรับ
        banner = s.recv(1024).decode('utf-8')
        print(banner, end="")

        # ส่ง Token ยืนยันตัวตน
        s.sendall(token.encode('utf-8') + b"\n")
        auth_resp = s.recv(1024).decode('utf-8')
        print(auth_resp)

        if "AUTH OK" in auth_resp:
            time.sleep(0.5)
            print(f"[*] Sending Vendor Command: '{command_to_run}'")
            s.sendall(command_to_run.encode('utf-8') + b"\n")
            cmd_resp = s.recv(1024).decode('utf-8')
            print(cmd_resp)

            s.sendall(b"exit\n")
        s.close()
    except Exception as e:
        print(f"[-] Connection Error: {e}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 vendor_client.py [TOKEN] [COMMAND]")
        print("Example: python3 vendor_client.py VENDOR-SECRET-KEY-99 read_status")
        sys.exit(1)

    token = sys.argv[1]
    cmd = sys.argv[2]
    run_vendor_client(token, cmd)

if __name__ == "__main__":
    main()
