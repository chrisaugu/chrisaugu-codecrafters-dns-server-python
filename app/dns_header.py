import struct
from dataclasses import dataclass, astuple
from ctypes import BigEndianStructure, c_uint16, c_uint8
from enum import Enum


TYPE_A = 1
CLASS_IN = 1
QR = 0
OPCODE = 1
RD = 2
RCODE = 3
fwdqueries = {}

class DNSHeader:
    # def __init__(self):
    #     # Initialize the DNS header fields with default values
    #     self.id = 1234  # Identifier
    #     self.qr = 1     # Query/Response Flag
    #     # Other flag fields: Opcode, AA, TC, RD, RA, Z, and RCODE
    #     self.opcode = self.aa = self.tc = self.rd = self.ra = self.z = self.rcode = 0
    #     # Initialize count fields for Question, Answer, Authority, and Additional sections
    #     self.qdcount = self.ancount = self.nscount = self.arcount = 0
    def __init__(
        self,
        hid: int = 1234,
        qr: int = 1,
        opcode: int = 0,
        aa: int = 0,
        tc: int = 0,
        rd: int = 0,
        ra: int = 0,
        z: int = 0,
        rcode: int = 0,
        qdcount: int = 1,
        ancount: int = 1,
        nscount: int = 0,
        arcount: int = 0,
    ):
        self.id = hid
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc 
        self.rd = rd
        self.ra = ra 
        self.z = z 
        self.rcode = rcode
        self.ancount = ancount
        self.qdcount = qdcount
        self.nscount = nscount
        self.arcount = arcount
    
    @staticmethod
    def from_bytes(message: bytes) -> "DNSHeader":
        # start & end indices in bytes
        start, end = (0, 6 * 2)
        header = message[start:end]
        hid, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", header
        )
        qr = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 0x1
        tc = (flags >> 9) & 0x1
        rd = (flags >> 8) & 0x1
        ra = (flags >> 7) & 0x1
        z = (flags >> 4) & 0x7
        rcode = flags & 0xF
        
        return DNSHeader(
            hid,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        )
        
    def to_bytes(self) -> bytes:
        # Combine the flag fields into a single 16-bit field
        flags = (
            (self.qr << 15)
            | (self.opcode << 11)
            | (self.aa << 10)
            | (self.tc << 9)
            | (self.rd << 8)
            | (self.ra << 7)
            | (self.z << 4)
            | self.rcode
        )
        # Pack the header fields into a bytes object
        return struct.pack(
            "!HHHHHH",
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

@dataclass
class DNSHeader2:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0

class QClass(Enum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4

class DNSRecordType(Enum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    ANY = 255
    
    MD = 3
    MF = 4
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    HINFO = 13
    MINFO = 14
    
class QTYPES(Enum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    ANY = 255

class TYPES(Enum):
    pass

@dataclass
class RDataType:
    preference: int
    exchange: int
    
@dataclass
class DNSHeader3:
    id: int = 16
    qr: int = 1
    opcode: int = 4
    aa: int = 0
    tc: int = 0
    rd: int = 1
    ra: int = 0
    z: int = 3
    rcode: int = 4
    qdcount: int = 16
    ancount: int = 16
    nscount: int = 16
    arcount: int = 16

@dataclass
class DNSQuestion3:
    qname: bytes
    qtype: int
    qclass: int


@dataclass
class DNSAnswer3:
    name: bytes
    atype: int
    aclass: int
    ttl: int
    rdlength: int
    rdata: bytes
    
@dataclass
class DNSAuthority3:
    pass

@dataclass
class DNSAncillary3:
    pass


class DNSMessage:
    header: DNSHeader3
    question: DNSQuestion3
    answer: DNSAnswer3
    authority: DNSAuthority3
    additional: DNSAncillary3


@dataclass
class DNSRecord:
    qname: bytes
    qtype: int
    qclass: int
    ttl: int
    data: bytes 


class DNSQuestion:
    def __init__(self, domain: str, qtype: str = 1, qclass: str = 1) -> None:
        self.qname = self.encode(domain)
        self.qtype = qtype
        self.qclass = qclass

    def encode(self, domain: str) -> bytes:
        return encode_str_to_bytes(domain)

    def to_bytes(self) -> bytes:
        return self.qname + struct.pack("!HH", self.qtype, self.qclass)

class DNSAnswer:
    def __init__(
        self,
        name: str,
        ip: str,
        atype: int = 1,
        aclass: int = 1,
        ttl: int = 60,
        rdlength: int = 4,
    ) -> None:
        self.name = self.encode(name)
        self.type = (atype).to_bytes(2, byteorder="big")
        self.aclass = (aclass).to_bytes(2, byteorder="big")
        self.ttl = (ttl).to_bytes(4, "big")
        self.length = (rdlength).to_bytes(2, "big")
        self.rdata = self.ipv4_to_bytes(ip)

    def encode(self, data: str) -> bytes:
        return encode_str_to_bytes(data)

    def ipv4_to_bytes(self, ip: str) -> bytes:
        res = b""
        for part in ip.split("."):
            res += int(part).to_bytes(1, "big")

        return res

    def to_bytes(self) -> bytes:
        return self.name + self.type + self.aclass + self.ttl + self.length + self.rdata

@dataclass
class DNSReplyPacket:
    # def __init__(
    #     id: int = 16, # mimic value
    #     qr: int = 1,
    #     opcode: int = 4, # mimic value
    #     aa: int = 0,
    #     tc: int = 0,
    #     rd: int = 1, # mimic value
    #     ra: int = 0, # mimic value
    #     z: int = 3, # mimic value
    #     rcode: int = 4,  # 0 (no error) if opcode is 0 (standard query) else 4 (not implemented)
    #     qdcount: int = 16,
    #     ancount: int = 16,
    #     nscount: int = 16,
    #     arcount: int = 16
    # ):
    #     pass
    id: int = 16 # mimic value
    qr: int = 1
    opcode: int = 4 # mimic value
    aa: int = 0
    tc: int = 0
    rd: int = 1 # mimic value
    ra: int = 0 # mimic value
    z: int = 3 # mimic value
    rcode: int = 4  # 0 (no error) if opcode is 0 (standard query) else 4 (not implemented)
    qdcount: int = 16
    ancount: int = 16
    nscount: int = 16
    arcount: int = 16

class ResourceRecord:
    def __init__(self, name: str, record_type: DNSRecordType, record_class: QClass, ttl: int, data: bytes):
        self.name = name
        self.record_type = record_type
        self.record_class = record_class
        self.ttl = ttl
        self.data = data



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

# from construct import Struct, Int16ub, BitsInteger, BitStruct
# class DNSHeader:
#     """
#         The header section is always 12 bytes long. Integers are encoded in big-endian format
#     """
#     __header_type = Struct(
#     "ID" / Int16ub,                # 16 bits |  A random ID assigned to query packets. Response packets must reply with the same ID
#     "flags" / BitStruct(
#         "QR" / BitsInteger(1),     # 1 bit   |  1 for a reply packet, 0 for a question packet
#         "OPCODE" / BitsInteger(4), # 4 bits  |  Specifies the kind of query in a message
#         "AA" / BitsInteger(1),     # 1 bit   |  if the responding server "owns" the domain queried, i.e., it's authoritative
#         "TC" / BitsInteger(1),     # 1 bit   |  if the message is larger than 512 bytes. Always 0 in UDP responses
#         "RD" / BitsInteger(1),     # 1 bit   |  Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise
#         "RA" / BitsInteger(1),     # 1 bit   |  sets this to 1 to indicate that recursion is available
#         "Z" / BitsInteger(3),      # 3 bits  |  Used by DNSSEC queries. At inception, it was reserved for future use
#         "RCODE" / BitsInteger(4),  # 4 bits  |  Response code indicating the status of the response
#     ),
#     "QDCOUNT" / Int16ub,           # 16 bits |  Number of questions in the Question section
#     "ANCOUNT" / Int16ub,           # 16 bits |  Number of records in the Answer section
#     "NSCOUNT" / Int16ub,           # 16 bits |  Number of records in the Authority section
#     "ARCOUNT" / Int16ub,           # 16 bits |  Number of records in the Additional section
#     )
#     __header = None
#     def __init__(self, id=1234, qr=1, opcode=0, aa=0, tc=0, rd=0, ra=0, z=0, rcode=0, qdc=0, anc=0, nsc=0, arc=0):
#         self.__header = self.__header_type.build(dict(ID=id, flags=dict(
#             QR=qr, OPCODE=opcode, AA=aa, TC=tc, RD=rd, RA=ra, Z=z, RCODE=rcode),
#             QDCOUNT=qdc,
#             ANCOUNT=anc,
#             NSCOUNT=nsc,
#             ARCOUNT=arc,
#         ))
#     def get_bytes(self) -> bytes:
#         return self.__header
#     def to_string(self) -> str:
#         if self.__header is None:
#             return ""
#         return self.__header_type.parse(self.__header)

class DNSHeader_RAW:
    """
    The header section is always 12 bytes long. Integers are encoded in big-endian format
    """
    __header = None
    def __init__(
        self,
        id=1234,
        qr=1,
        opcode=0,
        aa=0,
        tc=0,
        rd=0,
        ra=0,
        z=0,
        rcode=0,
        qdc=0,
        anc=0,
        nsc=0,
        arc=0,
    ):
        flags = (
            (qr << 15)  # 1 bit   -  1 for a reply packet, 0 for a question packet
            | (opcode << 11)  # 4 bits  -  Specifies the kind of query in a message
            | (aa << 10)  # 1 bit   -  if the responding server "owns" the domain queried, i.e., it's authoritative
            | (tc << 9)  # 1 bit   -  if the message is larger than 512 bytes. Always 0 in UDP responses
            | (rd << 8)  # 1 bit   -  Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise
            | (ra << 7)  # 1 bit   -  sets this to 1 to indicate that recursion is available
            | (z << 4)  # 3 bits  -  Used by DNSSEC queries. At inception, it was reserved for future use
            | (rcode)  # 4 bits  -  Response code indicating the status of the response
        )
        self.__header = struct.pack(">HHHHHH", id, flags, qdc, anc, nsc, arc)
        
    def get_bytes(self) -> bytes:
        return self.__header

class DNSHeader2(BigEndianStructure):
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

def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder="big")

def encode_bits(number, bit_length):
    return (0 << bit_length) | number

def packet_identifier():
    return 1234

def concatenate_bits(a, b):
    # Calculate the number of bits in b
    num_bits = b.bit_length()
    # Shift a left by the number of bits in b and combine with b
    return (a << num_bits) | b

def encode_str_to_bytes(data: str) -> bytes:
    parts = data.split(".")
    result = b""
    for part in parts:
        length = len(part)
        result += length.to_bytes(1, byteorder="big") + part.encode()
    result += b"\x00"
    return result

def header_to_bytes(header):
    fields = astuple(header)
    # there are 6 `H`s because there are 6 fields
    return struct.pack("!HHHHHH", *fields)

def question_to_bytes(question):
    return question.qname + struct.pack("!HH", question.qtype, question.qclass)

def createHeader():
    # response = format(int(1234), '016b') #pack_id
    response = bin(1234)
    response = response + format(int(1), "01b")  # query/response id
    response = response + format(int(0), "04b")  # opcode
    response = response + format(int(0), "01b")  # authoritative answer
    response = response + format(int(0), "01b")  # truncation
    response = response + format(int(0), "01b")  # recursion desired
    response = response + format(int(0), "01b")  # recursion available
    response = response + format(int(0), "03b")  # reserved
    response = response + format(int(0), "04b")  # response code
    response = response + format(int(0), "016b")  # question count
    response = response + format(int(0), "016b")  # ancount
    response = response + format(int(0), "016b")  # nscount
    response = response + format(int(0), "016b")  # arcount
    print(response)
    # response = b""
    
    return bitstring_to_bytes(response)

def create_dns_header() -> bytes:
    """
    Creates a 12-byte DNS header with the specified fields.
    All integers are encoded in big-endian format.
    Returns:
        bytes: A 12-byte header conforming to the DNS specification
    """
    # First 16 bits: Packet Identifier (ID)
    id = 1234
    # Next 16 bits: Various flags
    # We'll construct this using binary operations
    #
    # 1st flag - 8 bits
    # QR (1 bit): 1
    # OPCODE (4 bits): 0
    # AA (1 bit): 0
    # TC (1 bit): 0
    # RD (1 bit): 0
    # The bit shifting is a bit easier this to visualize if
    # all flags have their bits set:
    # 10000000  (qr) 1 << 7
    # 00001000  (opcode) 1 << 3
    # 00000100  (aa) 1 << 2
    # 00000010  (tc) 1 << 1
    # 00000001  (rd) 1
    # --------  OR them together (|)
    # 10001111  = 143 in decimal
    #
    flags1 = (1 << 7) | (0 << 3) | (0 << 2) | (0 << 1) | 0
    # 2nd flag - 8 bits
    # RA (1 bit): 0
    # Z (3 bits): 0
    # RCODE (4 bits): 0
    flags2 = (0 << 7) | (0)
    # Next four 16-bit fields
    qdcount = 0  # Question Count
    ancount = 0  # Answer Record Count
    nscount = 0  # Authority Record Count
    arcount = 0  # Additional Record Count
    # Pack everything into a binary string
    # '!' means network byte order (big-endian)
    # 'H' means 16-bit unsigned short
    # 'BB' means two 8-bit unsigned chars (for the flags)
    return struct.pack(
        "!HBBHHHH",
        id,  # 16 bits
        flags1,  # 8 bits
        flags2,  # 8 bits
        qdcount,  # 16 bits
        ancount,  # 16 bits
        nscount,  # 16 bits
        arcount,  # 16 bits
    )

def create_dns_question(name, n, m) -> bytes:
    label = name.split(".")
    qname = b"\x06" + label[0] + b"\x03" + label[1] + b"\x00"
    qtype = 2
    qclass = 2
    
    return struct.pack(
        "!HH",
        qname,
        qtype,
        qclass,
    )

def create_dns_query() -> bytes:
    header = create_dns_header()
    question = create_dns_question()
    
    return header + question

def create_dns_answer() -> bytes:
    pass

def build_dns_response(query):
    """
    Builds a DNS response based on the query received.
    """
    # Extract the DNS header and question section
    transaction_id = query[:2]  # Transaction ID from the query (2 bytes)
    flags = 0x8000  # QR=1, OPCODE=0, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
    # Extract QDCOUNT from the query header
    qdcount = struct.unpack("!H", query[4:6])[0]  # Number of questions
    # Fixed values for response (no answers or additional records)
    ancount = 0
    nscount = 0
    arcount = 0
    
    # Construct the DNS header using the transaction ID and fixed values
    dns_header = struct.pack(
        "!HHHHHH",
        struct.unpack("!H", transaction_id)[0],
        flags,
        qdcount,
        ancount,
        nscount,
        arcount,
    )
    # The question section starts after the header (12 bytes), copy it as-is
    dns_question = query[12:]
    # Combine the DNS header and question section to form the response
    dns_response = dns_header + dns_question
    return dns_response

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

def socket_from_addr(addr):
    ip, port = addr.split(":")
    return ip, int(port)

class DNSMessage:
    def __init__(self, buffer, src):
        if buffer:
            self.buf = buffer
            self.pid = buffer[:2]
            self.flags = int.from_bytes(buffer[2:4])
            self.qd_num = int.from_bytes(buffer[4:6])
            self.an_num = int.from_bytes(buffer[6:8])
            self.ns_num = int.from_bytes(buffer[8:10])
            self.ar_num = int.from_bytes(buffer[10:12])
        else:
            self.buf = b"\x00" * 12
            self.pid = b"\x00\x00"
            self.flags = 0
            self.qd_num = 0
            self.an_num = 0
            self.ns_num = 0
            self.ar_num = 0
        self.qtns = []
        self.awrs = []
        self.ipbyte = 8
        self.client = src
        
    def get_header(self):
        return (
            self.pid
            + self.flags.to_bytes(2)
            + len(self.qtns).to_bytes(2)
            + len(self.awrs).to_bytes(2)
            + self.ns_num.to_bytes(2)
            + self.ar_num.to_bytes(2)
        )
        
    def get_fwdhdr(self):
        qd_num = 1
        an_num = 1
        return (
            self.pid
            + self.flags.to_bytes(2)
            + qd_num.to_bytes(2)
            + an_num.to_bytes(2)
            + self.ns_num.to_bytes(2)
            + self.ar_num.to_bytes(2)
        )
        
    def update_flags(self, fwd_buf):
        self.flags = int.from_bytes(fwd_buf[2:4])
        
    def set_flag(self, fname, val=None):
        if fname == QR:
            self.flags |= 0x8000
        elif fname == OPCODE:
            self.flags |= val & 0x7800
        elif fname == RD:
            self.flags |= val & 0x0100
        elif fname == RCODE:
            self.flags |= 0 if self.get_opcode() == 0 else 4
            
    def get_opcode(self):
        return (self.flags & 0x7800) >> 11
    
    def add_q(self, qbuf):
        self.qtns.append(qbuf)
        self.qd_num += 1
        print("Q ADDED, ", self.qtns)
        
    def add_a(self, qbuf):
        ttlv = 60
        ttl = ttlv.to_bytes(4)
        dlenv = 4
        dlen = dlenv.to_bytes(2)
        data = b"\x08\x08\x08" + self.ipbyte.to_bytes(1)
        self.ipbyte += 1
        self.awrs.append(qbuf + ttl + dlen + data)
        self.an_num += 1
        print("A ADDED", self.awrs)
        
    def add_fwd_a(self, qbuf):
        self.awrs.append(qbuf)
        self.an_num += 1
        
    def make_msg(self):
        msg = self.get_header()
        for q in self.qtns:
            msg += q
        for a in self.awrs:
            msg += a
        return msg
    
    def make_fwdquery(self, sk, fwdaddr, c_addr):
        if ":" in fwdaddr:
            addr, port = fwdaddr.split(":")
            port = int(port)
        else:
            print("Error resolver info incorrect")
            exit()
        fwdquery = self.get_header() + self.qtns[-1]
        fwdqueries[self.get_header()[:2]] = self
        print("MSG TO SERVER", fwdquery)
        sk.sendto(fwdquery, 0, (addr, port))
        
    def qacountmatch(self):
        print("CHECKING ID:", self.pid)
        return len(self.qtns) == len(self.awrs)
    
    def get_raw_buf(self):
        return self.buf
    
    def send_query(self, sk, fwdaddr):
        header = self.get_fwdhdr()
        self.parse_questions()
        for q in self.qtns:
            query = header + q
            sk.sendto(query, fwdaddr)

    def parse_questions(self):
        bpos = 12
        qd_num = int.from_bytes(self.buf[4:6])
        for _ in range(qd_num):
            subbuf = b""
            while self.buf[bpos]:
                if self.buf[bpos] & 0xC0:
                    msg_offset = int.from_bytes(self.buf[bpos : bpos + 2]) & 0x3FFF
                    sect_end = msg_offset
                    while self.buf[sect_end]:
                        sect_end += 1
                    subbuf += self.buf[msg_offset:sect_end]
                    bpos += 1
                    break
                else:
                    subbuf_start = bpos
                    bpos += self.buf[bpos] + 1
                    subbuf += self.buf[subbuf_start:bpos]
            bpos += 1
            subbuf += b"\x00" + self.buf[bpos : bpos + 4]
            bpos += 4
            self.qtns.append(subbuf)
            print("QUESTIONS:", self.qtns)

def get_answer_from_server(sbuf, client):
    bpos = 12
    rcode = sbuf[4] & 0xF
    client.set_flag(RCODE, rcode)
    if bpos < len(sbuf):
        while sbuf[bpos]:
            if sbuf[bpos] & 0xC0:
                msg_offset = int.from_bytes(sbuf[bpos : bpos + 2]) & 0x3FFF
                sect_end = msg_offset
                while sbuf[sect_end]:
                    sect_end += 1
                bpos += 1
                break
            else:
                bpos += sbuf[bpos] + 1
        bpos += 5
        return sbuf[bpos:]
    return b""

class DNSMessage2:
    def __init__(
        self,
        header=bytearray(12),
        question=bytearray(12),
        answer=bytearray(12),
        authority=bytearray(12),
        space=bytearray(12),
    ):
        self.header = header
        self.question = question
        self.answer = answer
        self.authority = authority
        self.space = space
    def set_header(
        self,
        ID=0,
        QR=0,
        OPCODE=0,
        AA=0,
        TC=0,
        RD=0,
        RA=0,
        Z=0,
        RCODE=0,
        QDCOUNT=0,
        ANCOUNT=0,
        NSCOUNT=0,
        ARCOUNT=0,
    ):
        # set PID
        high_byte = (ID >> 8) & 0xFF
        low_byte = ID & 0xFF
        self.header[0] = high_byte
        self.header[1] = low_byte
        # set flags
        flags = (
            (QR << 15)
            | (OPCODE << 11)
            | (AA << 10)
            | (TC << 9)
            | (RD << 8)
            | (RA << 7)
            | (Z << 4)
            | (RCODE)
        )
        high_byte = (flags >> 8) & 0xFF
        low_byte = flags & 0xFF
        self.header[2] = high_byte
        self.header[3] = low_byte
        # set QDCOUNT
        high_byte = (QDCOUNT >> 8) & 0xFF
        low_byte = QDCOUNT & 0xFF
        self.header[4] = high_byte
        self.header[5] = low_byte
        # set ANCOUNT
        high_byte = (ANCOUNT >> 8) & 0xFF
        low_byte = ANCOUNT & 0xFF
        self.header[6] = high_byte
        self.header[7] = low_byte
        # set NSCOUNT
        high_byte = (NSCOUNT >> 8) & 0xFF
        low_byte = NSCOUNT & 0xFF
        self.header[8] = high_byte
        self.header[9] = low_byte
        # set ARCOUNT
        high_byte = (ARCOUNT >> 8) & 0xFF
        low_byte = ARCOUNT & 0xFF
        self.header[8] = high_byte
        self.header[9] = low_byte

    def get_header(self):
        return self.header


class DNSHeader:
    def __init__(
        self,
        hid: int = 1234,
        qr: int = 1,
        opcode: int = 0,
        aa: int = 0,
        tc: int = 0,
        rd: int = 0,
        ra: int = 0,
        z: int = 0,
        rcode: int = 0,
        qdcount: int = 1,
        ancount: int = 1,
        nscount: int = 0,
        arcount: int = 0,
    ):
        self.id = hid
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc 
        self.rd = rd
        self.ra = ra 
        self.z = z 
        self.rcode = rcode
        self.ancount = ancount
        self.qdcount = qdcount
        self.nscount = nscount
        self.arcount = arcount

    @staticmethod
    def from_bytes(message: bytes) -> "DNSHeader":
        # start & end indices in bytes
        start, end = (0, 6 * 2)
        header = message[start:end]
        hid, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", header
        )
        qr = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 0x1
        tc = (flags >> 9) & 0x1
        rd = (flags >> 8) & 0x1
        ra = (flags >> 7) & 0x1
        z = (flags >> 4) & 0x7
        rcode = flags & 0xF
        
        return DNSHeader(
            hid,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        )

    def to_bytes(self) -> bytes:
        flags = (
            (self.qr << 15)
            | (self.opcode << 11)
            | (self.aa << 10)
            | (self.tc << 9)
            | (self.rd << 8)
            | (self.ra << 7)
            | (self.z << 4)
            | (self.rcode)
        )
        return struct.pack(
            "!HHHHHH",
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

class DNSQuestion:
    def __init__(self, domain: str, qtype: int = 1, qclass: int = 1) -> None:
        self.qname = self.encode(domain)
        self.qtype = qtype
        self.qclass = qclass
        self.domain = domain

    def encode(self, domain: str) -> bytes:
        return encode_str_to_bytes(domain)

    def to_bytes(self) -> bytes:
        return self.qname + struct.pack("!HH", self.qtype, self.qclass)

    @staticmethod
    def from_bytes(message: bytes, qdcount: int) -> tuple[list['DNSQuestion'], int]:
        questions = []
        offset = 12  # Start after the header
        for _ in range(qdcount):
            domain, offset = DNSQuestion.parse_domain(message, offset)
            qtype, qclass = struct.unpack('!HH', message[offset:offset + 4])
            questions.append(DNSQuestion(domain, qtype, qclass))
            offset += 4
        return questions, offset
    
    @staticmethod
    def parse_domain(message: bytes, offset: int) -> tuple:
        return parse_domain(message, offset)

class DNSAnswer:
    def __init__(
        self,
        name: str,
        ip: str,
        atype: int = 1,
        aclass: int = 1,
        ttl: int = 60,
        rdlength: int = 4,
    ) -> None:
        self.name = self.encode(name)
        self.type = (atype).to_bytes(2, byteorder="big")
        self.aclass = (aclass).to_bytes(2, byteorder="big")
        self.ttl = (ttl).to_bytes(4, "big")
        self.length = (rdlength).to_bytes(2, "big")
        self.rdata = self.ipv4_to_bytes(ip)

    def encode(self, data: str) -> bytes:
        return encode_str_to_bytes(data)

    def ipv4_to_bytes(self, ip: str) -> bytes:
        res = b""
        for part in ip.split("."):
            res += int(part).to_bytes(1, "big")

        return res

    def to_bytes(self) -> bytes:
        return self.name + self.type + self.aclass + self.ttl + self.length + self.rdata
    
    @staticmethod
    def parse_domain(message: bytes, offset: int) -> tuple:
        return parse_domain(message, offset)
    
    @staticmethod
    def from_bytes(message: bytes, offset: int, ancount: int) -> tuple[list['DNSAnswer'], int]:
        answers = []
        for _ in range(ancount):
            name, offset = DNSAnswer.parse_domain(message, offset)
            atype, aclass, ttl, rdlength = struct.unpack('!HHIH', message[offset:offset + 10])
            offset += 10  # Advance offset past these fields
            rdata = message[offset:offset + rdlength]
            
            # If type is A (1), convert rdata to an IP address
            if atype == 1:
                ip = '.'.join(map(str, rdata))
            else:
                ip = ''  # Other record types not handled in this example

            answers.append(DNSAnswer(name, ip, atype, aclass, ttl, rdlength))
            offset += rdlength

        return answers, offset

def parse_domain(message: bytes, offset: int) -> tuple:
        labels = []
        while True:
            length = message[offset]
            if length & 0xC0 == 0xC0:  # Check for compression
                pointer = struct.unpack("!H", message[offset:offset+2])[0]
                offset += 2
                pointer &= 0x3FFF  # Remove the compression flag bits
                part, _ = DNSQuestion.parse_domain(message, pointer)
                labels.append(part)
                return '.'.join(labels), offset

            offset += 1  # Skip the length byte
            if length == 0:  # End of the domain name
                break

            labels.append(message[offset:offset+length].decode('utf-8'))
            offset += length

        return '.'.join(labels), offset

def forward_dns_query(query: bytes, dns_server: str, dns_port: int = 53) -> bytes:
    # Create a socket to communicate with the DNS server
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_socket:
        dns_socket.settimeout(2)  # Set a timeout for the DNS query
        # Send the DNS query to the specified DNS server
        dns_socket.sendto(query, (dns_server, dns_port))
        # Receive the response from the DNS server
        response, _ = dns_socket.recvfrom(4096)
    return response


            # # # Construct the DNS header with specified values
            # # ID = 1234
            # # QR = 1  # Set to 1 for response
            # # OPCODE = 0
            # # AA = 0
            # # TC = 0
            # # RD = 0
            # # RA = 0
            # # Z = 0
            # # RCODE = 0
            # # QDCOUNT = 0
            # # ANCOUNt = 0
            # # NSCOUNT = 0
            # # ARCOUNT = 0
            # # # Pack the header fields into bytes
            # # packed_id = struct.pack("!H", ID)
            # # # Correctly set QR bit as the highest-order bit in the first flag byte
            # # flags_byte1 = (QR << 7) | (OPCODE << 3) | AA << 6 | TC << 5 | RD << 4
            # # flags_byte2 = RA | (Z << 1) | (RCODE << 4)
            # # packed_flags = struct.pack("!BB", flags_byte1, flags_byte2)
            # # packed_qdcount = struct.pack("!H", QDCOUNT)
            # # packed_ancount = struct.pack("!H", ANCOUNt)
            # # packed_nscount = struct.pack("!H", NSCOUNT)
            # # packed_arcount = struct.pack("!H", ARCOUNT)
            # # response_header = (
            # #     packed_id
            # #     + packed_flags
            # #     + packed_qdcount
            # #     + packed_ancount
            # #     + packed_nscount
            # #     + packed_arcount
            # # )
            
            # # # Send the response back
            # # udp_socket.sendto(response_header, source)
            
            
            
            
            # # bufhdr = buf[:12]
            # # msgid = bufhdr[:2]
            # # print("FROM SOURCE:", source)
            # # print("BUF:", buf)
            
            # # if msgid in fwdqueries.keys():
            # #     cdns = fwdqueries[msgid]
            # #     awr = get_answer_from_server(buf, cdns)
            # #     client = cdns.client
            # #     cdns.awrs.append(awr)
            # #     print("ANSWERS:", cdns.awrs)
            # #     if cdns.qacountmatch():
            # #         cdns.set_flag(QR)
            # #         response = cdns.make_msg()
            # #         print("TO CLIENT:", response)
            # #         udp_socket.sendto(response, client)
            # #         del fwdqueries[msgid]
            # #     """
            # #     print("FROM SERVER:",buf)
            # #     dnsq = fwdqueries[qid]
            # #     dnsq.update_flags(bufhdr)
            # #     qd_num = int.from_bytes(bufhdr[4:6])
            # #     bpos = 12
            # #     for _ in range(qd_num):
            # #         while buf[bpos]:
            # #             if buf[bpos] & 0xc0:
            # #                 msg_offset = int.from_bytes(buf[bpos:bpos+2]) & 0x3fff
            # #                 sect_end = msg_offset
            # #                 while buf[sect_end]:
            # #                     sect_end += 1
            # #                 bpos += 1
            # #                 break
            # #             else:
            # #                 bpos += buf[bpos]+1
            # #         bpos += 5
            # #     for an in dnsq.awrs:
            # #         print("ANSWER:",an)
            # #     dnsq.add_fwd_a(buf[bpos:])
            # #     #if dnsq.qacountmatch() or dnsq.an_num > dnsq.qd_num:
            # #     response = dnsq.make_msg()
            # #     print("FINAL MSG:",response)
            # #     udp_socket.sendto(response,dnsq.client_addr)
            # #     dnsq.qd_num = 0
            # #     dnsq.an_num = 0
            # #     #else:
            # #     #print("MISMATCH:",dnsq.qd_num,dnsq.an_num)
            # #     """
            # # else:
            # #     # bpos = 12
            # #     # dmsg = DNSMessage(buf)
            # #     rsp = DNSMessage(buf, source)
            # #     # qd_num = int.from_bytes(bufhdr[4:6])
            # #     fwdqueries[buf[:2]] = rsp
            # #     rsp.send_query(udp_socket, socket_from_addr(sys.argv[2]))
            # #     """
            # #     for _ in range(qd_num):
            # #         subbuf = b""
            # #         while buf[bpos]:
            # #             if buf[bpos] & 0xc0:
            # #                 msg_offset = int.from_bytes(buf[bpos:bpos+2]) & 0x3fff
            # #                 sect_end = msg_offset
            # #                 while buf[sect_end]:
            # #                     sect_end += 1
            # #                 subbuf += buf[msg_offset:sect_end]
            # #                 bpos += 1
            # #                 break
            # #             else:
            # #                 subbuf_start = bpos
            # #                 bpos += buf[bpos]+1
            # #                 subbuf += buf[subbuf_start:bpos]
            # #         bpos += 1
            # #         subbuf += b"\x00" + buf[bpos:bpos+4]
            # #         bpos += 4
            # #         rsp.add_q(subbuf)
            # #         rsp.make_fwdquery(udp_socket,sys.argv[2],source)
            # #         """
            # # """
            # # bpos = 12
            # # dmsg = DNSMessage(buf)
            # # rsp = DNSMessage(buf)
            # # qd_num = int.from_bytes(bufhdr[4:6])
            # # for _ in range(qd_num):
            # #     subbuf = b""
            # #     while buf[bpos]:
            # #         if buf[bpos] & 0xc0:
            # #             msg_offset = int.from_bytes(buf[bpos:bpos+2]) & 0x3fff
            # #             sect_end = msg_offset
            # #             while buf[sect_end]:
            # #                 sect_end += 1
            # #             subbuf += buf[msg_offset:sect_end]
            # #             bpos += 1
            # #             break
            # #         else:
            # #             subbuf_start = bpos
            # #             bpos += buf[bpos]+1
            # #             subbuf += buf[subbuf_start:bpos]
            # #     bpos += 1
            # #     subbuf += b"\x00" + buf[bpos:bpos+4]
            # #     bpos += 4
            # #     rsp.add_q(subbuf)
            # #     rsl_flag = "--resolver"
            # #     if rsl_flag in sys.argv:
            # #         forwarding = sys.argv.index(fsl_flag) + 1
            # #         rsp.make_fwdquery(udp_socket,forwarding,source)
            # #     rsp.add_a(subbuf)
            # #     qd_buf = b""
            
            # # print("CL_MSG:",buf)
            # # dmsg = DNSMessage(buf)
            # # rsp = DNSMessage()
            # # rsp.pid = dmsg.pid
            # # rsp.set_flag(QR)
            # # rsp.set_flag(OPCODE,dmsg.flags)
            # # rsp.set_flag(RD,dmsg.flags)
            # # rsp.set_flag(RCODE)
            
            # # bpos = 12
            # # for _ in range(dmsg.qd_num):
            # #     subbuf = b""
            # #     while buf[bpos]:
            # #         if buf[bpos] & 0xc0:
            # #             msg_offset = int.from_bytes(buf[bpos:bpos+2]) & 0x3fff
            # #             sect_end = msg_offset
            # #             while buf[sect_end]:
            # #                 sect_end += 1
            # #             subbuf += buf[msg_offset:sect_end]
            # #             bpos += 1
            # #             break
            # #         else:
            # #             subbuf_start = bpos
            # #             bpos += buf[bpos]+1
            # #             subbuf += buf[subbuf_start:bpos]
            # #     bpos += 1
            # #     subbuf += b"\x00" + buf[bpos:bpos+4]
            # #     bpos += 4
            # #     rsp.add_q(subbuf)
            # #     rsp.add_a(subbuf)
            # #     qd_buf = b""
            # #     """
            # # # response = rsp.make_msg()
            # # # print("RSP:",response)
            # # # udp_socket.sendto(response, source)
            # # print("MSG HANDLED")

def encode_dns_name(domain_name):
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"

def build_dns_header(data: bytes) -> bytes:
    id = 16
    qr = 1
    opcode = 0
    aa = 0
    tc = 0
    rd = 0
    ra = 0
    z = 0
    rcode = 0
    qdcount = 0
    ancount = 0
    nscount = 0
    arcount = 0
    
    return struct.pack(
        "!HHHHHH",
        id,
        qr,
        opcode,
        aa,
        tc,
        rd,
        ra,
        z,
        rcode,
        qdcount,
        ancount,
        nscount,
        arcount
    )
    

def parse_header(message: bytes):
    # Unpack the first 12 bytes of the DNS header
    data = message[:12]
    header = struct.unpack('!HHHHHHHH', data)
    # fields = struct.unpack("!HHHHHH", data)
    # hid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data)
    # header = DNSReplyPacket(hid, flags, qdcount, ancount, nscount, arcount)
    # fields = astuple(header)
    # return fields
    
    # Extract fields from the header
    dns_id = header[0]
    qr = (header[1] >> 15) & 0x01          # QR flag
    opcode = (header[1] >> 11) & 0x0F       # Opcode
    aa = (header[1] >> 10) & 0x01           # Authoritative Answer
    tc = (header[1] >> 9) & 0x01            # Truncated
    rd = (header[1] >> 8) & 0x01            # Recursion Desired
    ra = (header[1] >> 7) & 0x01            # Recursion Available
    z = (header[1] >> 4) & 0x07              # Reserved
    ad = (header[1] >> 3) & 0x01            # Authenticated Data
    cd = (header[1] >> 2) & 0x01            # Checking Disabled
    rcode = header[1] & 0x0F                # Response Code

    # Return extracted values in a dictionary
    return {
        'id': dns_id,
        'qr': qr,
        'opcode': opcode,
        'aa': aa,
        'tc': tc,
        'rd': rd,
        'ra': ra,
        'z': z,
        'ad': ad,
        'cd': cd,
        'rcode': rcode,
        'qdcount': header[2],
        'ancount': header[3],
        'nscount': header[4],
        'arcount': header[5]
    }

def parse_question(message: bytes):
    qname = decode_name_simple(message)
    data = message[:4]
    qtype, qclass = struct.unpack("!HH", data)
    return DNSQuestion(qname, qtype, qclass)

def parse_record(message: bytes):
    qname = decode_name_simple(message)
    # the the type, class, TTL, and data length together are 10 bytes (2 + 2 + 4 + 2 = 10)
    # so we read 10 bytes
    data = message[:10]
    # HHIH means 2-byte int, 2-byte-int, 4-byte int, 2-byte int
    qtype, qclass, ttl, data_len = struct.unpack("!HHIH", data) 
    data = message.read(data_len)
    return DNSRecord(qname, qtype, qclass, ttl, data)

def build_dns_answer():
    qname = b""
    qtype = b""
    qclass = b""
    ttl = 0
    rdlength = 0
    rdata = 0
    
    return struct.pack("", qname, qtype, qclass, ttl, rdlength, rdata)

def decode_name_simple(message: bytes):
    parts = []
    # while (length := message[:1][0]) != 0:
    #     parts.append(message[length])
    # return b".".join(parts)
    # message[:1][0].decode("ascii")
    print(message[1])
    

def DNStoDict(hdr: bytes):
    '''
    Parse QNAME by using length (byte) +data sequence -- final length=0 signifies end of QNAME
    Refer to https://stackoverflow.com/questions/34841206/why-is-the-content-of-qname-field-not-the-original-domain-in-a-dns-message

    1) DNS knows nothing of URLs. DNS is older than the concept of a URL.

    2) Because that's how DNS's wire format works. What you see is the 
       domain name www.mydomain.com, encoded in the DNS binary format. 
       Length+data is a very common way of storing strings in general.
    '''

        # Build DNS dictionary of values... include QNAME
    l = len(hdr)
    argSize = hdr[10]*256+hdr[11]
    dnsDict = dict(ID     = hdr[0]*256+hdr[1],
                   QR     = bool(hdr[2] & int('10000000', 2)),
                   Opcode =     (hdr[2] & int('01111000', 2))>>3,
                   AA     = bool(hdr[2] & int('00000100', 2)),
                   TC     = bool(hdr[2] & int('00000010', 2)),
                   RD     = bool(hdr[2] & int('00000001', 2)),
                   RA     = bool(hdr[3] & int('10000000', 2)),
                   Z      = bool(hdr[3] & int('01000000', 2)),
                   AD     = bool(hdr[3] & int('00100000', 2)),
                   CD     = bool(hdr[3] & int('00010000', 2)),
                   RCode  = bool(hdr[3] & int('00001111', 2)),
                   QDCOUNT = hdr[4]*256+hdr[5],
                   ANCOUNT = hdr[6]*256+hdr[7],
                   NSCOUNT = hdr[8]*256+hdr[9],
                   ARCOUNT = argSize,
                   QTYPE   = hdr[l-4]*256+hdr[l-3],
                   QCLASS   = hdr[l-2]*256+hdr[l-2])

    # Parse QNAME
    n = 12
    mx = len(hdr)
    qname = ''

    while n < mx:
        try:
            qname += hdr[n:n+argSize].decode() + '.'

            n += argSize
            argSize = int(hdr[n])
            n += 1
            if argSize == 0 : 
                break
        except Exception as err:
            print("Parse Error", err, n, qname)
            break
    dnsDict['QNAME'] = qname[:-1]
    return dnsDict

# Sample DNS Packet Data 
# hdr = b'\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03www\x10googletagmanager\x03com\x00\x00\x01\x00\x01'

# Parse out the QNAME
# dnsDict = DNStoDict(hdr)

# print("\n DNS PACKET dictionary")
# print(dnsDict)

def decode_qname(data: bytes, offset):
    """
    Decodes a QNAME from a DNS packet.

    Args:
        data: The DNS packet as a byte string.
        offset: The offset (in bytes) where the QNAME starts.

    Returns:
        A tuple containing:
            - The decoded QNAME as a string.
            - The offset of the next field after the QNAME.
    """
    domain_name = ""
    current_offset = offset
    while True:
        length = data[current_offset]
        current_offset += 1

        if length == 0:
            break  # End of QNAME

        label = data[current_offset:current_offset + length].decode()
        # "ascii")
        # .decode('utf-8')
        domain_name += label + "."
        current_offset += length

    return domain_name[:-1], current_offset  # Remove trailing dot