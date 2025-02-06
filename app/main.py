import struct
import socket, sys
# from app.response import build_dns_response
# from app.dns import create_dns_header
from . import dns 
from . import message
from . import response as res

def main():
    print("Logs from your program will appear here!")

    # UDP socket is created and bound to the local address 127.0.0.1 and port 2053
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
    
            # response = b"\x04\xd2\x80" + (b"\x00" * 9)
            # response = b""
            
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
            
            # # udp_socket.sendto(response, source)
            
            
            # dnsmsg = DNSMessage2()
            # dnsmsg.set_header(1234, 1)
            # header = dnsmsg.get_header()
            # response = header
            
            print(f"Received {len(buf)} from {source}")
            
            header = dns.create_dns_header()
            # question = create_dns_question(b"google.com", 1, 1)
            response = b"" + header
            # response = res.build_dns_response(header)
            
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
