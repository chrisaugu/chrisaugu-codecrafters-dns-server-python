import struct
import socket, sys
# from app.response import build_dns_response
# from app.dns import create_dns_header
# from . import dns 
# from . import message
# from . import response as res
import dns

def main():
    print("Logs from your program will appear here!")

    # UDP socket is created and bound to the local address 127.0.0.1 and port 2053
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512) # Receive 512 bytes of data from the client
    
            # response = b"\x04\xd2\x80" + (b"\x00" * 9)
            # response = b""
            
            # dnsmsg = DNSMessage2()
            # dnsmsg.set_header(1234, 1)
            # header = dnsmsg.get_header()
            # response = header
            
            print(f"Received {len(buf)} from {source}")
            print(f"Received {buf} from {source}")
            
            header = dns.create_dns_header()
            question_section = buf[12:]
            # question = dns.create_dns_question(b"google.com", 1, 1)
            # response = res.build_dns_response(header)
            response = header + question_section
            
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
