import socket
import threading
import sys

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 502
PLC_IP = "172.20.0.20"
PLC_PORT = 5020

ALLOW_WRITE = True                 # สิทธิ์แก้ไขค่าเครื่องจักร (Write)
IPS_VIRTUAL_PATCH_ENABLED = False  # ระบบอุดช่องโหว่เสมือน (Virtual Patching Mode)

def handle_client(client_socket):
    try:
        plc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plc_socket.connect((PLC_IP, PLC_PORT))
    except Exception as e:
        print(f"[-] Cannot connect to PLC: {e}")
        client_socket.close()
        return

    def forward(src, dst, direction):
        global ALLOW_WRITE, IPS_VIRTUAL_PATCH_ENABLED
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break

                if direction == "inbound":
                    if len(data) >= 8:
                        function_code = data[7]

                        # [TASK 1: Deep Packet Inspection (DPI) & Granular Access Control]
                        if function_code in [6, 16]: # คำสั่งเขียนข้อมูลลง Register (Write)
                            print(f"[🛡️ DPI Alert] Detected Modbus WRITE Command (FC: {function_code})")
                            if not ALLOW_WRITE:
                                print("[🚫 Firewall Block] Policy 'Block-Write' is ACTIVE! Dropping writing command.")
                                src.send(b"\x00\x02\x00\x00\x00\x03\x01\x86\x01")
                                break

                        # [TASK 2: Virtual Patching with IPS Mode]
                        elif function_code == 90:
                            print(f"[🚨 IPS Critical Alert] Detected Exploit Payload targeting PLC Modbus firmware (FC: 90)!")
                            if IPS_VIRTUAL_PATCH_ENABLED:
                                print("[🔒 Virtual Patch Blocked] IPS virtual patch signature matched! Intercepted exploit packet. PLC remains safe.")
                                src.send(b"\x00\x03\x00\x00\x00\x03\x01\xda\x04")
                                break
                            else:
                                print("[⚠️ WARNING] Virtual Patch is DISABLED. Exploit packet forwarded to PLC SCADA!")

                        else:
                            print(f"[🟢 DPI Pass] Allowed Modbus READ Command (FC: {function_code})")

                dst.sendall(data)
        except Exception:
            pass
        finally:
            src.close()
            dst.close()

    t1 = threading.Thread(target=forward, args=(client_socket, plc_socket, "inbound"))
    t2 = threading.Thread(target=forward, args=(plc_socket, client_socket, "outbound"))
    t1.start()
    t2.start()

def main():
    global ALLOW_WRITE, IPS_VIRTUAL_PATCH_ENABLED
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_IP, LISTEN_PORT))
    server.listen(5)
    print(f"[*] NGFW/DPI Engine listening on {LISTEN_IP}:{LISTEN_PORT}...")
    print(f"[*] Policy State: ALLOW_WRITE={ALLOW_WRITE} | IPS_VIRTUAL_PATCH={IPS_VIRTUAL_PATCH_ENABLED}")
    while True:
        client_sock, addr = server.accept()
        print(f"[+] Active Session established with client {addr[0]}:{addr[1]}")
        threading.Thread(target=handle_client, args=(client_sock,)).start()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if "block-write" in sys.argv:
            ALLOW_WRITE = False
        if "enable-ips" in sys.argv:
            IPS_VIRTUAL_PATCH_ENABLED = True
    main()
