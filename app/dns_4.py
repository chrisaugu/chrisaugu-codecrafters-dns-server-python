import socket
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
import struct
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
            | (
                aa << 10
            )  # 1 bit   -  if the responding server "owns" the domain queried, i.e., it's authoritative
            | (
                tc << 9
            )  # 1 bit   -  if the message is larger than 512 bytes. Always 0 in UDP responses
            | (
                rd << 8
            )  # 1 bit   -  Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise
            | (
                ra << 7
            )  # 1 bit   -  sets this to 1 to indicate that recursion is available
            | (
                z << 4
            )  # 3 bits  -  Used by DNSSEC queries. At inception, it was reserved for future use
            | (rcode)  # 4 bits  -  Response code indicating the status of the response
        )
        self.__header = struct.pack(">HHHHHH", id, flags, qdc, anc, nsc, arc)
    def get_bytes(self) -> bytes:
        return self.__header
####################################################################################################
def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            obj = DNSHeader_RAW(
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
            )
            response = obj.get_bytes()
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break
####################################################################################################
if __name__ == "__main__":
    main()