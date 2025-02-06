import struct

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