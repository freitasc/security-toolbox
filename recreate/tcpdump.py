# Recreates tcpdump basic funcionality using python
# I basically just wanted to see how well i could do it
# I'm not sure if this is useful for anything, tcpdump is a great tool and has many more features than this
# But it was a fun little project to work on while I was bored on a café

import socket
import struct
import textwrap

# create a socket and bind it to the interface
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
conn.bind(('wlp3s0', 0))

# main loop
while True:
    # capture packet
    raw_data, addr = conn.recvfrom(65535)
    
    # parse ethernet header
    eth_header = raw_data[:14]
    eth_fields = struct.unpack("!6s6sH", eth_header)
    dest_mac = eth_fields[0]
    src_mac = eth_fields[1]
    eth_type = socket.ntohs(eth_fields[2])
    
    # skip non-IP packets
    if eth_type != 8:
        continue
    
    # parse IP header
    ip_header = raw_data[14:34]
    ip_fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
    version_ihl = ip_fields[0] >> 4
    ihl = ip_fields[0] & 0xF
    tos = ip_fields[1]
    total_length = ip_fields[2]
    identification = ip_fields[3]
    flags_offset = ip_fields[4]
    ttl = ip_fields[5]
    protocol = ip_fields[6]
    ip_checksum = ip_fields[7]
    src_ip = socket.inet_ntoa(ip_fields[8])
    dest_ip = socket.inet_ntoa(ip_fields[9])
    
    # parse TCP header
    tcp_header = raw_data[34:54]
    tcp_fields = struct.unpack("!HHLLBBHHH", tcp_header)
    src_port = tcp_fields[0]
    dest_port = tcp_fields[1]
    sequence = tcp_fields[2]
    ack = tcp_fields[3]
    doff_reserved = tcp_fields[4]
    flags = tcp_fields[5]
    window = tcp_fields[6]
    tcp_checksum = tcp_fields[7]
    urg_pointer = tcp_fields[8]
    
    # print packet info
    packet_info = f"Ethernet Frame: {src_mac} -> {dest_mac} Type: {eth_type}"
    packet_info += f"\nFlags: {flags} Window: {window} Checksum: {tcp_checksum}"
    packet_info += f"\nSequence: {sequence} Acknowledgement: {ack} URG: {urg_pointer}"
    packet_info += f"\nIP Packet: {src_ip} -> {dest_ip} Protocol: {protocol}"
    packet_info += f"\nTCP Segment: {src_port} -> {dest_port}"
    packet_info += f"\n\n"
    print(packet_info)
    
    