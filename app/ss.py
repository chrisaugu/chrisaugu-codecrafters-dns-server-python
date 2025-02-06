import socket
import traceback
import struct
from dataclasses import dataclass
@dataclass
class Packet:
    id: int
    qr_indicator: bool  # True -> Reply, False -> Query
    opcode: int
    is_authoritative: bool
    truncation: bool  # 1 if > 512 bytes 0 in udp
    recursion_desired: bool
    recursion_available: bool
    reserved: int  # 3 bytes
    response_code: int
    q_count: int  # Question count
    an_count: int  # Answer count
    ns_count: int  # No of records
    ar_count: int  # additional record count
    @staticmethod
    def build_req(buf: bytes) -> "Packet":
        identifier = int.from_bytes(buf[:2])
        qr_to_rd = buf[2]
        ra_z_r_code = buf[3]
        qd_count = buf[4:6]
        an_count = buf[6:8]
        ns_count = buf[8:10]
        ar_count = buf[10:]
        qr = qr_to_rd & 0b10000000 > 1
        opcode = (qr_to_rd & 0b01111000) >> 3
        aa = (qr_to_rd & 0b00000100) > 0
        tc = qr_to_rd & 0b00000010 > 0
        rd = qr_to_rd & 0b000000001 > 0
        ra = ra_z_r_code & 0b10000000 > 0
        reserved = (ra_z_r_code & 0b01110000) >> 4
        response_code = (ra_z_r_code << 4) >> 4
        return Packet(
            id=identifier,
            qr_indicator=qr,
            opcode=opcode,
            is_authoritative=aa,
            truncation=tc,
            recursion_desired=rd,
            recursion_available=ra,
            reserved=reserved,
            response_code=response_code,
            q_count=int.from_bytes(qd_count),
            an_count=int.from_bytes(an_count),
            ns_count=int.from_bytes(ns_count),
            ar_count=int.from_bytes(ar_count),
        )
    def __repr__(self) -> str:
        return f"{self.__dict__}"
    def to_bytes(self) -> bytes:
        builder = [
            int_to_bin(self.id, 16),
            bool_to_bin(self.qr_indicator),
            int_to_bin(self.opcode, 4),
            bool_to_bin(self.is_authoritative),
            bool_to_bin(self.truncation),
            bool_to_bin(self.recursion_desired),
            bool_to_bin(self.recursion_available),
            int_to_bin(self.reserved, 3),
            int_to_bin(self.response_code, 4),
            int_to_bin(self.q_count, 16),
            int_to_bin(self.an_count, 16),
            int_to_bin(self.ns_count, 16),
            int_to_bin(self.ar_count, 16),
        ]
        bin_str = "".join(builder)
        return bitstring_to_bytes(bin_str)
def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xFF)
        v >>= 8
    return bytes(b[::-1])
def bool_to_bin(val: bool) -> str:
    return str(int(val))
def int_to_bin(val: int, bit_width: int) -> str:
    return bin(val)[2:].zfill(bit_width)
def parse_request(buf: bytes) -> bytes:
    """Parse the request from the server"""
    pkt = Packet.build_req(buf)
    return get_response(pkt)
default_resp = Packet(
    id=1234,
    qr_indicator=True,
    opcode=0,
    is_authoritative=False,
    truncation=False,
    recursion_desired=False,
    recursion_available=0,
    reserved=0,
    response_code=0,
    q_count=0,
    an_count=0,
    ns_count=0,
    ar_count=0,
)

def get_response(pkt: Packet) -> bytes:
    return default_resp.to_bytes()

def main():
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            response = parse_request(buf)
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {traceback.format_exc()}")
            break
