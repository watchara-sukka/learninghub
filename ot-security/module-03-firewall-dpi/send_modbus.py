import socket
import sys

IP = "172.19.0.10"
PORT = 502

def send_packet(payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((IP, PORT))
        s.sendall(payload)
        response = s.recv(1024)
        print(f"[*] Sent (Hex): {payload.hex()}")
        print(f"[+] Received (Hex): {response.hex()}")

        if len(response) >= 9:
            function_code = response[7]
            exception_code = response[8]
            if function_code & 0x80:
                print(f"[🚫] Server returned MODBUS EXCEPTION: {exception_code}")
                if exception_code == 1:
                    print("    ↳ Reason: Illegal Function (คำสั่งแก้ไขข้อมูลเขียนทับ ถูกบล็อกโดยระบบรักษาความปลอดภัย DPI)")
                elif exception_code == 4:
                    print("    ↳ Reason: Slave Device Failure (ตรวจพบสัญญานอันตรายเจาะช่องโหว่ ถูกสกัดโดยระบบ Virtual Patch IPS)")
            else:
                print("[🟢] Command completed successfully! (ส่งผ่านพัสดุข้อมูลสำเร็จ)")
        s.close()
    except Exception as e:
        print(f"[-] Connection Error: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 send_modbus.py [read|write|exploit]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "read":
        print("[*] Sending Modbus READ HOLDING REGISTERS (FC: 03)...")
        packet = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"
        send_packet(packet)
    elif cmd == "write":
        print("[*] Sending Modbus WRITE SINGLE REGISTER (FC: 06)...")
        packet = b"\x00\x02\x00\x00\x00\x06\x01\x06\x00\x00\x00\xff"
        send_packet(packet)
    elif cmd == "exploit":
        print("[*] Sending simulated FIRMWARE EXPLOIT packet (FC: 90)...")
        packet = b"\x00\x03\x00\x00\x00\x06\x01\x5a\xaa\xbb\xcc\xdd"
        send_packet(packet)
    else:
        print("Usage: python3 send_modbus.py [read|write|exploit]")

if __name__ == "__main__":
    main()
