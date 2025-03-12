import socket
import struct
import random
import fcntl
import sys

# EtherType for IPv4
ETH_P_IP = 0x0800
# Function to get the IP address
def get_ip_address(interface):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', interface[:15].encode()))
        return socket.inet_ntoa(info[20:24])
    except OSError as e:
        print(f"Error getting IP address for {interface}: {e}")
        sys.exit(1)

# Function to calculate TCP checksum
#Ref- “Calculation of TCP Checksum,” GeeksforGeeks, Mar. 30, 2020. https://www.geeksforgeeks.org/calculation-of-tcp-checksum/
def tcp_cheksum(source_ip, dest_ip, tcp_header, payload=b''):
    # Pseudo header for TCP checksum
    pseudo_header = struct.pack('!4s4sBBH',
        socket.inet_aton(source_ip),
        socket.inet_aton(dest_ip),
        0,  # Reserved
        socket.IPPROTO_TCP,  # Protocol (TCP)
        len(tcp_header) + len(payload)  # TCP length
    )

    # Combining pseudo header, TCP header, and payload
    combined_packet = pseudo_header + tcp_header + payload

    # Ensuring even length for checksum calculation
    if len(combined_packet) % 2 != 0:
        combined_packet += b'\x00'  # Pad with zero byte

    # Calculating checksum
    cheksum = 0
    for i in range(0, len(combined_packet), 2):
        word = (combined_packet[i] << 8) + combined_packet[i + 1]
        cheksum += word
        cheksum &= 0xffffffff  # Truncating to 32 bits

    cheksum = (cheksum >> 16) + (cheksum & 0xffff)
    cheksum += (cheksum >> 16)
    cheksum = ~cheksum & 0xffff  
    return cheksum

# Function to create a TCP SYN packet
def create_tcp_syn(source_ip, dest_ip, source_port, dest_port):
    # Ref- GeeksforGeeks, “TCP/IP Packet Format,” GeeksforGeeks, Sep. 11, 2023. https://www.geeksforgeeks.org/tcp-ip-packet-format/
    # TCP header fields
    #Choosing a random sequence number becuase sequence number is used to identify the order of the packets
    seq_num = random.randint(0, 0xffffffff)
    ack_num = 0
    data_offset = 5  # 5 * 4 = 20 bytes
    reserved = 0
    flags = 0x02  # SYN flag
    window_size = socket.htons(5840)  # Typical window size
    urgent_pointer = 0

    # TCP header
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

    # Calculate checksum
    cheksum = tcp_cheksum(source_ip, dest_ip, tcp_header)
    # Pack TCP header with checksum
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

# Function to create IP header
def create_ip_header(source_ip, dest_ip, tcp_header, payload=b''):
    version_iphl = (4 << 4) | 5  # IPv4 and IHL=5 (no options)
    tos = 0
    # Total length will be IP header + TCP header + payload
    total_length = 20 + len(tcp_header) + len(payload) 
    total_length = socket.htons(total_length)
    identification = 0xFFFF
    flags_fragment_offset = 0
    ttl = 64  # Time to live
    protocol = socket.IPPROTO_TCP  # TCP Protocol
    source_ip = socket.inet_aton(source_ip)
    destination_ip = socket.inet_aton(dest_ip)

    # Pack IP header
    ip_header = struct.pack('!BBHHHBBH4s4s',
        version_iphl,
        tos,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        0,
        source_ip,
        destination_ip
    )

    return ip_header

# Function to send TCP SYN packet using raw sockets
def send_tcp_syn(dest_ip, source_port, dest_port):
    # Create TCP SYN packet
    interface = "eth0"
    source_ip = get_ip_address(interface)
    tcp_header= create_tcp_syn(source_ip, dest_ip, source_port, dest_port)

    # Create IP header
    ip_header = create_ip_header(source_ip, dest_ip, tcp_header)

    # Create a raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # Tell the kernel not to add a IP header
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.bind((source_ip, source_port))

    # Construct the entire packet
    packet = ip_header + tcp_header

    # Send the TCP SYN packet
    try:
        sock.sendto(packet, (dest_ip, dest_port))
        print(f'TCP SYN packet sent to {dest_ip}:{dest_port}')
    except socket.error as e:
        print(f"Sending Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    #Manually add the destination IP address, ports to be used, easy to change later
    dest_ip = "10.0.1.21"
    # Random source port
    source_port = 0x6789
    # Port 80
    dest_port = 0x50 

    send_tcp_syn(dest_ip, source_port, dest_port)
