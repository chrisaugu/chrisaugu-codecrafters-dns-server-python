while True:
        try:
            buf, source = udp_socket.recvfrom(512)
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
            print(bitstring_to_bytes(response))
            # response = b""
            udp_socket.sendto(bitstring_to_bytes(response), source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break
def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder="big")
def encode_bits(number, bit_length):
    return (0 << bit_length) | number
def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder="big")
def packet_identifier():
    return 1234
def concatenate_bits(a, b):
    # Calculate the number of bits in b
    num_bits = b.bit_length()
    # Shift a left by the number of bits in b and combine with b
    return (a << num_bits) | b
if __name__ == "__main__":
    main()