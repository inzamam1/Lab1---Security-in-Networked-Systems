import socket
import struct
import binascii
import sys
import signal

# REf- “Packet sniffer in Python.” Available: https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf

#For all the Ethernet based protocols
ETH_P_ALL = 0x0003  

# Function to parse Ethernet header
def parse_eth_header(packet):
    eth_head = packet[:14]
    #reverse of what we did in create_ethernet_frame
    eth_field = struct.unpack("!6s6sH", eth_head)
    #Get the destination MAC, source MAC and EtherType
    destination_mac = binascii.hexlify(eth_field[0]).decode("utf-8")
    source_mac = binascii.hexlify(eth_field[1]).decode("utf-8")
    eth_typ = eth_field[2]
    return destination_mac, source_mac, eth_typ

# Function to parse IP header
def parse_ip_header(packet):
    #The first 14 bytes are for the Ethernet header, so next 20 is IP header
    ip_head = packet[14:34] 
    #reverse of what we did in create_ip_header 
    ip_fields = struct.unpack("!BBHHHBBH4s4s", ip_head)
    version_iphl = ip_fields[0]
    #extracting the version, higher bits
    version = version_iphl >> 4
    #Getting the length, lower bits
    ihl = version_iphl & 0xF
    tos = ip_fields[1]
    total_len = ip_fields[2]
    proto = ip_fields[6]
    #Extracting the source and destination IP addresses 
    src_ip = socket.inet_ntoa(ip_fields[8])
    dest_ip = socket.inet_ntoa(ip_fields[9])
    return version, ihl, tos, total_len, proto, src_ip, dest_ip

# Function to parse TCP header (if present)
def parse_tcp_header(packet):
    # As we saw above the IP header is 20 bytes, so the TCP header starts at 34
    tcp_start = 34
    # TCP header is 20 bytes
    tcp_header = packet[tcp_start:tcp_start + 20]  
    tcp_field = struct.unpack("!HHLLBBHHH", tcp_header)
    source_port = tcp_field[0]
    destination_port = tcp_field[1]
    sequence_num = tcp_field[2]
    acknowledgment_num = tcp_field[3]
    return source_port, destination_port, sequence_num, acknowledgment_num

# Handling exit on SIGINT (Ctrl+C)
def signal_handler(sig, frame):
    print("\n Stopping sniffer...")
    sys.exit(0)

# Main function to sniff packets
def sniffer():
    try:
        # Creating raw socket to sniff and display packets
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))

        print("sniffer started. Press Ctrl+C to stop.\n")
        #Loop to keep listneing for packets
        while True:
            # Receive a packet
            packet, addr = sock.recvfrom(65535)

            # Start from parsing the Ethernet header
            dest_mac, src_mac, eth_type = parse_eth_header(packet)
            print(f"Ethernet Header:")
            print(f"Destination MAC: {':'.join(dest_mac[i:i+2] for i in range(0, len(dest_mac), 2))}")
            print(f"Source MAC: {':'.join(src_mac[i:i+2] for i in range(0, len(src_mac), 2))}")
            print(f"EtherType: {hex(eth_type)}")

            # Checking if the packet is an IP packet - EthType == 0x0800
            if eth_type == 0x0800:
                version, ihl, tos, total_len, protocol, source_ip, destination_ip = parse_ip_header(packet)
                print(f"\nIP Header:")
                print(f"Version: {version}")
                print(f"IHL: {ihl} words ({ihl * 4} bytes)")
                print(f"TOS: {tos}")
                print(f"Total Length: {total_len}")
                print(f"Protocol: {protocol}")
                print(f"Source IP: {source_ip}")
                print(f"Destination IP: {destination_ip}")

                # Checking if the packet is a TCP packet - Protocol == 6
                if protocol == 6:
                    source_port, destination_port, sequence_num, acknowledgment_num = parse_tcp_header(packet)
                    print(f"\nTCP Header:")
                    print(f"Source Port: {source_port}")
                    print(f"Destination Port: {destination_port}")
                    print(f"Sequence Number: {sequence_num}")
                    print(f"Acknowledgment Number: {acknowledgment_num}")
            print("\n" + "-" * 25 + "\n")

    except KeyboardInterrupt:
        # Registering signal handler for Ctrl+C
        signal_handler(None, None) 
    except socket.error as e:
        print(f"Socket error: {e}")
        sock.close()
        exit()

if __name__ == "__main__":
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    sniffer()