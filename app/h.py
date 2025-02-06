from ctypes import BigEndianStructure, c_uint16, c_uint8
import socket

class DNSHeader(BigEndianStructure):
    _fields_ = [
        ("id", c_uint16),  # Transaction ID
        ("qr", c_uint8, 1),  # Query/Response flag (0 = query, 1 = response)
        ("opcode", c_uint8, 4),  # Operation code (0 = standard query)
        ("aa", c_uint8, 1),  # Authoritative Answer flag
        ("tc", c_uint8, 1),  # Truncation flag
        ("rd", c_uint8, 1),  # Recursion Desired flag
        ("ra", c_uint8, 1),  # Recursion Available flag
        ("z", c_uint8, 3),  # Reserved bits (must be zero)
        ("rcode", c_uint8, 4),  # Response code (0 = no error)
        ("qdcount", c_uint16),  # Number of questions in question section
        ("ancount", c_uint16),  # Number of answers in answer section
        ("nscount", c_uint16),  # Number of authority records
        ("arcount", c_uint16),  # Number of additional records
    ]
    
def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            print(f"received {len(buf)} bytes")
            header = DNSHeader()
            header.id = 1234
            header.qr = 1
            response = bytes(header)
            print(f"response bytes: {response}")
            udp_socket.sendto(response, source)
        except Exception as e:
            