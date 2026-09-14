import struct
import string

def parse_dns(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    offset = 24
    queries = []
    while offset < len(data):
        if offset + 16 > len(data): break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', data[offset:offset+16])
        offset += 16
        packet = data[offset:offset+incl_len]
        offset += incl_len
        
        if len(packet) >= 42:
            protocol = packet[23]
            if protocol == 17: # UDP
                ip_header_len = (packet[14] & 0x0f) * 4
                src_port = struct.unpack('>H', packet[14+ip_header_len : 14+ip_header_len+2])[0]
                dst_port = struct.unpack('>H', packet[14+ip_header_len+2 : 14+ip_header_len+4])[0]
                if dst_port == 53 or src_port == 53:
                    dns_payload = packet[14+ip_header_len+8:]
                    if len(dns_payload) > 12:
                        # Extract query name
                        q_offset = 12
                        domain = []
                        while q_offset < len(dns_payload):
                            length = dns_payload[q_offset]
                            if length == 0:
                                break
                            if (length & 0xC0) == 0xC0: # Pointer
                                break
                            q_offset += 1
                            domain.append(dns_payload[q_offset:q_offset+length].decode('ascii', errors='ignore'))
                            q_offset += length
                        if domain:
                            queries.append(".".join(domain))
                            
    with open(r'c:\Users\User\Desktop\hotmart 2.0\results_dns.txt', 'w') as f:
        for q in queries:
            f.write(q + "\n")
    print("Done! Check results_dns.txt")

try:
    parse_dns(r'c:\Users\User\Desktop\hotmart 2.0\industrial_meltdown.pcap')
except Exception as e:
    print(f"Error: {e}")
