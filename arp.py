import socket
import struct
import fcntl
import sys

# ARP opcodes
# Ref - “Address Resolution Protocol (ARP) Parameters,” www.iana.org. https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
ARP_REQUEST = 1
ETH_P_ARP = 0x0806  # EtherType for ARP

# Function to get the MAC address unlike the previous ICMP scripts where the MAC address was hardcoded
# We are also fetching the IP address using ioctl and fcntl as we are manually forming the ARP packet
# “The fcntl and ioctl System Calls in Python,” Tutorialspoint.com, 2019. https://www.tutorialspoint.com/the-fcntl-and-ioctl-system-calls-in-python
def get_mac_address(interface):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface[:15].encode()))
        return info[18:24]
    except OSError as e:
        print(f"Error getting MAC address for {interface}: {e}")
        sys.exit(1)

# Function to get the IP address
def get_ip_address(interface):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', interface[:15].encode()))
        return socket.inet_ntoa(info[20:24])
    except OSError as e:
        print(f"Error getting IP address for {interface}: {e}")
        sys.exit(1)

def create_ethernet_frame(src_mac):
    # Destination MAC address is broadcast address as we don't know the MAC address of the destination
    destination_mac = b'\xff\xff\xff\xff\xff\xff'
    # Ethernet frame: Destination MAC (6 bytes), Source MAC (6 bytes), EtherType (2 bytes), Payload (variable length)
    ethernet_header = struct.pack("!6s6sH", destination_mac, src_mac, ETH_P_ARP)
    return ethernet_header

# Function to create an ARP Request packet
def create_arp_request(src_mac, src_ip, dst_ip):
    # Ref “ARP Protocol Packet Format,” GeeksforGeeks, Feb. 14, 2023. https://www.geeksforgeeks.org/arp-protocol-packet-format/
    source_ip = socket.inet_aton(src_ip)
    destination_ip = socket.inet_aton(dst_ip)
    destination_mac = b'\x00\x00\x00\x00\x00\x00'
    # Creating Ethernet frame
    eth_hdr = create_ethernet_frame(src_mac)

    # ARP header
    arp_hdr = struct.pack('!HHBBH6s4s6s4s',
        0x0001,  # Hardware type (Ethernet)
        0x0800,  # Protocol type (IPv4)
        6,        # Hardware size (MAC length)
        4,        # Protocol size (IP length)
        ARP_REQUEST,  # Opcode (ARP Request)
        src_mac,  # Sender MAC
        source_ip,  # Sender IP
        destination_mac,  # Target MAC (unknown)
        destination_ip  # Target IP
    )
    return eth_hdr + arp_hdr

# Function to send ARP Request and listen for a reply
def send_arp_request(dest_ip):
    # Creating a raw socket for Ethernet frames and ARP packets
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    # Bind to the interface
    sock.bind(("eth0", 0))

    # Getting the source MAC and IP address using ioctl and fcntl
    src_mac = get_mac_address("eth0")
    src_ip = get_ip_address("eth0")

    # Create ARP Request packet
    arp_request = create_arp_request(src_mac, src_ip, dest_ip)

    # Send the packet
    sock.send(arp_request)
    print(f"ARP Request sent to {dest_ip}")


if __name__ == '__main__':
    #Manually add the destination IP address, easy to change later
    dest_ip = "10.0.1.21"
    send_arp_request(dest_ip)
