import struct
import socket, sys
import traceback
from dns_header import QTYPES, DNSAnswer, DNSHeader, DNSQuestion, create_dns_header, build_dns_response, forward_dns_query, parse_header, build_dns_header, encode_dns_name, decode_name_simple, DNStoDict, decode_qname, parse_question_section

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
            print(f"Received {len(buf)} bytes from {source}")
            print(f"Received data from {source}: {buf}")
            
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
            
            # header = DNSHeader()
            # header.id = 1234
            # header.qr = 1
            # response = bytes(header)
            # response = header.to_bytes()
            # print(f"response bytes: {response}")
            # response = parse_request(buf)

            # response = b"\x04\xd2\x80" + (b"\x00" * 9)
            
            # dnsmsg = DNSMessage2()
            # dnsmsg.set_header(1234, 1)
            # header = dnsmsg.get_header()
            # response = header
            
            # header = create_dns_header()
            # question_section = buf[12:]
            # question = dns.create_dns_question(b"google.com", 1, 1)
            # response = res.build_dns_response(header)
            
            # int.to_bytes(0x01020304, length=4, byteorder='little')
            # int.to_bytes(0x01020304, length=4, byteorder='big')
            
            # header = rid + rflags + qdcount + ancount + (b"\x00" * 6)
            # header = build_dns_header(buf)
            # rid, rflags, qdcount, ancount, nscount, arcount = parse_header(buf)

            # parse message header
            rid, rflags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", buf[:12])
            # rid = b"\x04\xd2" #(1234).to_bytes(2, byteorder='big') struct.pack('>h', 1234)
            qr = 1
            # opcode = 0
            aa  = 0
            tc = 0
            # rd = 1
            ra = 0
            z = 0
            rcode = 4
            # dns_id = rid
            # qr = (rflags >> 15) & 0x01
            opcode = (rflags >> 11) & 0x0F
            # aa = (rflags >> 10) & 0x01
            # tc = (rflags >> 9) & 0x01
            rd = (rflags >> 8) & 0x01
            # ra = (rflags >> 7) & 0x01
            # z = (rflags >> 4) & 0x07
            # ad = (rflags >> 3) & 0x01
            # cd = (rflags >> 2) & 0x01
            # rcode = rflags & 0x0F
            
            # qdcount= b"\x00\x01"
            # ancount = b"\x00\x01"

            # packing
            rflags = (
                (qr << 15) |
                (opcode << 11) |
                (aa << 10) |
                (tc << 9) |
                (rd << 8) |
                (ra << 7) |
                (z << 4) |
                # (ad << 3) |
                # (cd << 2) |
                rcode
            )
            # rflags = (1 << 7) | (1 << 3) | (0 << 2) | (0 << 1) | 1
            # rflags2 = (0 << 7) | (0)
       
            # header = struct.pack(
            #     "!HHHHHH", 
            #     # "!HBBHHHH",
            #     rid, 
            #     rflags,
            #     # rflags2,
            #     qdcount, 
            #     ancount, 
            #     nscount, 
            #     arcount
            # )
            
            print(parse_question_section(buf[12:], 0, qdcount))
            
            # questions = bytearray()
            # for question in range(qdcount):
            #     # loop this part to parse each question
            #     # qname = decode_name_simple(buf)
            #     qname, next_offset = decode_qname(buf, 12)
            #     qname = encode_dns_name(qname)
            #     # qtype = b"\x00\x01"
            #     qtype = (1).to_bytes(2, byteorder='big')
            #     # qclass = b"\x00\x01"
            #     qclass = (1).to_bytes(2, byteorder='big')
            #     question = qname + qtype + qclass
            #     questions.append(question)
            
            # answers = bytearray()
            # for question in questions:
            #     # for each parsed query perform dns lookup/resolve
            #     # resource records  
            #     qname, next_offset = decode_qname(buf, 12)
            #     qname = encode_dns_name(qname)
            #     # qtype = b"\x00\x01"
            #     qtype = (1).to_bytes(2, byteorder='big')
            #     # qclass = b"\x00\x01"
            #     qclass = (1).to_bytes(2, byteorder='big')
            #     ttl = (60).to_bytes(4, byteorder='big')
            #     rdata = b"\x08\x08\x08\x08"
            #     rdlength = len(rdata).to_bytes(2, byteorder='big')
            #     answer = question + ttl + rdlength + rdata
            #     answers.append(answer)

            # # set id, qr=1, ancount, other flags
            # ancount = len(answers)
            # header = struct.pack(
            #     "!HHHHHH", 
            #     rid, 
            #     rflags,
            #     qdcount, 
            #     ancount, 
            #     nscount, 
            #     arcount
            # )
            
            # response = header + questions + answers
            response = b""

            # header = DNSHeader.from_bytes(buf)
            # # overwrite received flags for our reply
            
            # print(DNStoDict(buf))
            
            # header.qr, header.ancount, header.arcount, header.nscount = 1, 1, 0, 0
            # domain = "codecrafters.io"
            # q = DNSQuestion(domain)
            # a = DNSAnswer(domain, "8.8.8.8")
            
            # response = header.to_bytes() + q.to_bytes() + a.to_bytes()
            
            udp_socket.sendto(response, source)
            
        except Exception as e:
            print(f"Error receiving data: {e} {traceback.format_exc()}")
            break

def mainx():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolver", required=False, default=None)
    args = parser.parse_args()
    print("Starting UDP server...")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 2053))
        
        while True:
            data, addr = s.recvfrom(512)
            # h1 = DNSHeader.from_bytes(data)
            # data = b'\xc0\x90\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x03def\xc0\x10\x00\x01\x00\x01'
            print(f"Received data from {addr}: {data}")
            query_header = DNSHeader.from_bytes(data)

            # Parsing the question section
            query_questions, questions_offset = DNSQuestion.from_bytes(data, query_header.qdcount)
            response_header = DNSHeader(
                hid=query_header.id,  # Match the query's ID
                qr=1,  # This is a response
                opcode=query_header.opcode,
                aa=0,
                tc=0,  # Not truncated
                rd=query_header.rd,
                ra=0,  # Recursion not available
                z=0,
                rcode=0 if not query_header.opcode else 4,
                qdcount=query_header.qdcount,
                ancount=len(query_questions),  # Assuming one answer per question
                nscount=0,
                arcount=0
            )

            if args.resolver:
                host, port = args.resolver.split(":")
                port = int(port)
                aggregated_answers = []

                for question in query_questions:
                    # Forward each question separately
                    fw_header = DNSHeader(
                        hid=query_header.id,  # Keep the original ID
                        qr=0,  # Query
                        opcode=query_header.opcode,
                        aa=0,
                        tc=0,
                        rd=query_header.rd,
                        ra=0,
                        z=0,
                        rcode=0,
                        qdcount=1,  # Only one question
                        ancount=0,
                        nscount=0,
                        arcount=0
                    )
                    fw_query = fw_header.to_bytes() + question.to_bytes()
                    fw_response = forward_dns_query(fw_query, host, port)

                    # Parse the response and aggregate answers
                    fw_header_res = DNSHeader.from_bytes(fw_response)
                    offset = 12  # Start after the header
                    _, offset = DNSQuestion.from_bytes(fw_response, fw_header_res.qdcount)  # Skip questions
                    fw_answers, _ = DNSAnswer.from_bytes(fw_response, offset, fw_header_res.ancount)
                    aggregated_answers.extend(fw_answers)

                # Construct the final response
                response_header.qdcount = query_header.qdcount
                response_header.ancount = len(aggregated_answers)
                response = response_header.to_bytes() + data[12:questions_offset]
                for answer in aggregated_answers:
                    response += answer.to_bytes()
            else:
                # Constructing the question section for the response
                response_questions = b''.join(q.to_bytes() for q in query_questions)

                # Constructing the answer section
                response_answers = b''
                for q in query_questions:
                    if q.qtype == 1:  # Process if QTYPE is A
                        a = DNSAnswer(q.domain, "8.8.8.8", q.qtype, q.qclass)
                        response_answers += a.to_bytes()

                # Assembling the full response
                response = response_header.to_bytes() + response_questions + response_answers
            print(f'response is {response}')
            print(f'Sending response to {addr}')
            s.sendto(response, addr)

if __name__ == "__main__":
    mainx()
