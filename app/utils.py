# see https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format
# left-to-right for easier reading
HEADER_SIZES = [
    ("T_ID", 16),
    ("QR", 1),
    ("OPCODE", 4),
    ("AA", 1),
    ("TC", 1),
    ("RD", 1),
    ("RA", 1),
    ("Z", 1),
    ("AD", 1),
    ("CD", 1),
    ("RCODE", 4),
    ("num_qts", 16),
    ("num_aws", 16),
    ("num_authrr", 16),
    ("num_addrr", 16),
]

def make_header(**kwargs):
    pos, header = 0, 0
    for name, length in reversed(HEADER_SIZES):
        header += kwargs.get(name, 0) << pos
        pos += length
    return header.to_bytes(12)