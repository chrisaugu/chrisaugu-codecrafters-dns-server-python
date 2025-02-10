import socket, sys
import traceback
from .dns_header import DNSAnswer, DNSHeader, DNSQuestion, create_dns_header, build_dns_response

def main():
    print("Starting UDP server...")
    print("Logs from your program will appear here!")

    # UDP socket is created and bound to the local address 127.0.0.1 and port 2053
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            # data, addr = udp_socket.recvfrom(512)
            buf, source = udp_socket.recvfrom(512) # Receive 512 bytes of data from the client
            
            # response = DNS(
            #     id=1234,
            #     qr=1,
            #     opcode=0,
            #     aa=0,
            #     tc=0,
            #     rd=0,
            #     ra=0,
            #     z=0,
            #     rccode=0,
            #     qdcount=0,
            #     andcount=0,
            #     nscount=0,
            #     arcount=0,
            # ).header
            
            # obj = DNSHeader_RAW(
            #     id=1234,
            #     qr=1,
            #     opcode=0,
            #     aa=0,
            #     tc=0,
            #     rd=0,
            #     ra=0,
            #     z=0,
            #     rcode=0,
            #     qdc=0,
            #     anc=0,
            #     nsc=0,
            #     arc=0,
            # )
            # response = obj.get_bytes()
            
            # print(f"received {len(buf)} bytes")
            # header = DNSHeader()
            # header.id = 1234
            # header.qr = 1
            # response = bytes(header)
            # response = header.to_bytes()
            # print(f"response bytes: {response}")
            # response = parse_request(buf)

            # response = b"\x04\xd2\x80" + (b"\x00" * 9)
            # response = b""
            
            # dnsmsg = DNSMessage2()
            # dnsmsg.set_header(1234, 1)
            # header = dnsmsg.get_header()
            # response = header
            
            print(f"Received {len(buf)} from {source}")
            print(f"Received data from {source}: {buf}")
            
            # header = create_dns_header()
            # question_section = buf[12:]
            # question = dns.create_dns_question(b"google.com", 1, 1)
            # response = res.build_dns_response(header)
            
            # rid = b"\x04\xd2"
            # rflags = b"\x80\00"
            # qdcount= b"\x00\x01"
            # header = rid + rflags + qdcount + (b"\x00" * 6)
            # question_section = b"\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"
            
            # response = header + question_section
            
            header = DNSHeader.from_bytes(buf)
            # ovwerrite received flags for our reply
            header.qr, header.ancount, header.arcount, header.nscount = 1, 1, 0, 0
            domain = "codecrafters.io"
            q = DNSQuestion(domain)
            a = DNSAnswer(domain, "8.8.8.8")
            response = header.to_bytes() + q.to_bytes() + a.to_bytes()
            
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e} {traceback.format_exc()}")
            break

if __name__ == "__main__":
    main()
