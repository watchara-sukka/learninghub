import docker
import time
import json

client = docker.from_env()

TRUSTED_OUI = "00:0e:8c" # Siemens OUI
INGRESS_NET = "ingress-net"
PRODUCTION_NET = "production-net"
QUARANTINE_NET = "quarantine-net"

inventory = {}

def print_cmdb_table():
    print("\n" + "="*85)
    print(" 🖥️  OT ASSET INVENTORY (CMDB) - UPDATED REALTIME")
    print("="*85)
    print(f"{'Device Name':<16} | {'MAC Address':<18} | {'Vendor (OUI)':<12} | {'Purdue Level':<24} | {'Segment/VLAN':<16}")
    print("-"*85)
    for name, details in inventory.items():
        print(f"{name:<16} | {details['mac']:<18} | {details['vendor']:<12} | {details['level']:<24} | {details['network']:<16}")
    print("="*85 + "\n")

print("🛡️ NAC Controller is running and monitoring ports...")

def monitor_and_segment():
    try:
        network = client.networks.get(INGRESS_NET)
    except docker.errors.NotFound:
        return

    containers = network.attrs.get('Containers', {})
    for container_id, info in containers.items():
        name = info.get('Name')
        if name in ['nac-controller'] or name in inventory:
            continue

        mac_addr = info.get('MacAddress', '')
        if not mac_addr:
            continue

        # Passive Profiling & CMDB Entry
        if mac_addr.startswith(TRUSTED_OUI):
            vendor = "Siemens"
            level = "Level 1 (Basic Control)"
            assigned_net = PRODUCTION_NET
        else:
            vendor = "Unknown"
            level = "Level 4 (Enterprise/IT)"
            assigned_net = QUARANTINE_NET

        inventory[name] = {
            "mac": mac_addr,
            "vendor": vendor,
            "level": level,
            "network": assigned_net
        }

        print_cmdb_table()

        # Dynamic Segmentation Action
        network.disconnect(container_id)
        client.networks.get(assigned_net).connect(container_id)
        print(f"🔒 [Dynamic Segmentation] Moved {name} to designated VLAN [{assigned_net}]\n")

        try:
            with open("asset_inventory.json", "w") as f:
                json.dump(inventory, f, indent=4)
        except:
            pass

while True:
    monitor_and_segment()
    time.sleep(2)