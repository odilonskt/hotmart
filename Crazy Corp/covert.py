import struct
import base64

def check_flag(s):
    if b"donotecho" in s.lower() or b"flag" in s.lower():
        print("FOUND:", s)
        return True
    return False

with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
magic = struct.unpack('<I', data[0:4])[0]
endian = '<' if magic == 0xA1B2C3D4 else '>'
offset = 24

ip_ids = []
tcp_seqs = []
tcp_acks = []
icmp_data = bytearray()
tcp_urg = []
dns_queries = []

while offset < len(data) - 16:
    incl_len = struct.unpack(endian + 'I', data[offset+8:offset+12])[0]
    pkt = data[offset+16:offset+16+incl_len]
    offset += 16 + incl_len
    
    if len(pkt) > 34 and struct.unpack('>H', pkt[12:14])[0] == 0x0800:
        ip = pkt[14:]
        if len(ip) < 20: continue
        ip_id = struct.unpack('>H', ip[4:6])[0]
        ip_ids.append(ip_id)
        
        proto = ip[9]
        ihl = (ip[0] & 0xF) * 4
        
        if proto == 1: # ICMP
            if len(ip) > ihl + 8:
                icmp_data.extend(ip[ihl+8:])
                
        elif proto == 6: # TCP
            tcp = ip[ihl:]
            if len(tcp) >= 20:
                seq = struct.unpack('>I', tcp[4:8])[0]
                ack = struct.unpack('>I', tcp[8:12])[0]
                urg = struct.unpack('>H', tcp[18:20])[0]
                tcp_seqs.append(seq)
                tcp_acks.append(ack)
                tcp_urg.append(urg)

print("Checking IP IDs (high/low bytes)...")
ip_bytes = bytearray()
for id in ip_ids:
    ip_bytes.append(id >> 8)
    ip_bytes.append(id & 0xFF)

for k in range(256):
    b = bytes([x ^ k for x in ip_bytes])
    check_flag(b)

print("Checking TCP Seqs...")
seq_bytes = bytearray()
for seq in tcp_seqs:
    seq_bytes.extend(struct.pack('>I', seq))
for k in range(256):
    b = bytes([x ^ k for x in seq_bytes])
    check_flag(b)

print("Checking ICMP data...")
for k in range(256):
    b = bytes([x ^ k for x in icmp_data])
    check_flag(b)

print("Checking TCP Urgent Pointers...")
urg_bytes = bytearray()
for urg in tcp_urg:
    urg_bytes.append(urg >> 8)
    urg_bytes.append(urg & 0xFF)
for k in range(256):
    b = bytes([x ^ k for x in urg_bytes])
    check_flag(b)

print("Done covert channel check.")
