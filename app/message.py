import struct
import socket, sys


QR = 0
OPCODE = 1
RD = 2
RCODE = 3
fwdqueries = {}

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
