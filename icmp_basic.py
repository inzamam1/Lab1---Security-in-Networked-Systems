#!/usr/bin/env python3
import socket
import struct

def cheksum(packet):
    #Calculating the checksum of the packet
    # Ref R. T. Braden, D. A. Borman, and C. Partridge, “Computing the Internet checksum,” Sep. 1988, doi: https://doi.org/10.17487/rfc1071.
    # REF- “Python and socket library - Raspberry Pi Forums,” Raspberrypi.com, 2024. https://forums.raspberrypi.com/viewtopic.php?t=362742
    # Calculate the ICMP checksum
    cheksum = 0
    for i in range(0, len(packet), 2):
        cheksum += (packet[i] << 8) + (
            struct.unpack('B', packet[i + 1:i + 2])[0]
            if len(packet[i + 1:i + 2]) else 0
        )

    cheksum = (cheksum >> 16) + (cheksum & 0xFFFF)
    cheksum = ~cheksum & 0xFFFF
    return cheksum

def create_icmp_packet():
    # ICMP Echo Request has:
    # type = 8, code = 0 id, sequence
    # Ref-“ICMP (Internet Control Message Protocol),” NetworkLessons.com, Jul. 22, 2015. https://networklessons.com/cisco/ccie-routing-switching-written/icmp-internet-control-message-protocol
    # ICMP ID to identify our packet (ideally unique and using some random number) but for now,I have kept it 0xFFFF
    icmp_id = 0xFFFF
    icmp_type = 8
    icmp_code = 0
    sequence=1
    # Here we are creating the header of the ICMP packet, but checksum is inititalized to 0 as we will calculate it later
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

def icmp_echo(dest_addr):
    try:
        # Trying to create a raw socket
        # Type - Af.INET which is IPv4, type of socket is raw socket, IPPROTO_ICMP is ICMP protocol for ping packets
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # Telling the kernel not to add IP header, but no need to do right now as I am not manially adding IP header
        #sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except Exception as e:
        print("Error:", e)
        return
    # Once the socket is created, we can create the ICMP packet
    packet = create_icmp_packet()
    dest_ip = socket.gethostbyname(dest_addr)
    print(f"Sending ICMP Echo Request to {dest_ip}")
    try:
        sock.sendto(packet, (dest_ip, 1))
        print("Packet sent")
    except Exception as e:
        print("Failed to send packet:", {e})
        return

if __name__ == '__main__':
    #Manually add the destination IP address, easy to change later
    dest_addr = "10.0.0.21"
    icmp_echo(dest_addr)
