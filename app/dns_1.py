import socket
from dataclasses import dataclass
# dig @127.0.0.1 -p 2053 +noedns codecrafters.io
@dataclass
class DNS:
    id: int  # Packet Identifier (ID)             16 bits
    qr: int  # Query/Response Indicator (QR)      1 bit
    opcode: int  # Operation Code (OPCODE)            4 bits
    aa: int  # Authoritative Answer (AA)          1 bit
    tc: int  # Truncation (TC)                    1 bit
    rd: int  # Recursion Desired (RD)             1 bit
    ra: int  # Recursion Available (RA)           1 bit
    z: int  # Reserved (Z)                       3 bits
    rccode: int  # Response Code (RCODE)              4 bits
    qdcount: int  # Question Count (QDCOUNT)           16 bits
    andcount: int  # Answer Record Count (ANCOUNT)      16 bits
    nscount: int  # Authority Record Count (NSCOUNT)   16 bits
    arcount: int  # Additional Record Count (ARCOUNT)  16 bits
    
    @property
    def header(self) -> bytes:
        header = bytearray(12)
        header[0] = self.id >> 8
        header[1] = self.id & 0xFF
        header[2] = (self.qr << 7 | self.opcode << 3 | self.aa << 2 | self.tc << 1 | self.rd)
        header[3] = self.ra << 7 | self.z << 4 | self.rccode
        header[4] = self.qdcount
        header[5] = self.andcount
        header[6] = self.nscount
        header[7] = self.arcount
        return header

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            
            response = DNS(
                id=1234,
                qr=1,
                opcode=0,
                aa=0,
                tc=0,
                rd=0,
                ra=0,
                z=0,
                rccode=0,
                qdcount=0,
                andcount=0,
                nscount=0,
                arcount=0,
            ).header
            udp_socket.sendto(response, source)
        except Exception as e: