# simple firewall detection script
# scans all ports of a given IP address and checks if they are open, closed or filtered
import sys
from scapy.all import *

# python firewall_detect.py IP
ip = sys.argv[1]

# scan all ports (CAUTION, THIS MIGHT TAKE A WHILE AND IS VERY NOISY)
for port in range(1, 1025):
    # create a SYN packet
    packet = IP(dst=ip) / TCP(dport=port, flags="S")

    # send the packet and wait for a response
    response = sr1(packet, timeout=1, verbose=0)

    # check response
    if response is not None:
        # check if the response contains a SYN/ACK flag
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"Port {port} is open")
        else:
            print(f"Port {port} is closed")
            
    else:
        print(f"No response from {ip}:{port}")