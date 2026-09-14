import struct

def extract_invisible():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    offset = 24
    
    ip_ids = []
    tcp_seqs = []
    
    while offset < len(data) - 16:
        incl_len = struct.unpack(endian + 'I', data[offset+8:offset+12])[0]
        pkt = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(pkt) > 54 and struct.unpack('>H', pkt[12:14])[0] == 0x0800:
            ip = pkt[14:]
            ip_id = struct.unpack('>H', ip[4:6])[0]
            ip_ids.append(ip_id)
            
            if len(ip) > 20 and ip[9] == 6:
                ihl = (ip[0] & 0xF) * 4
                tcp = ip[ihl:]
                if len(tcp) >= 20:
                    seq = struct.unpack('>I', tcp[4:8])[0]
                    tcp_seqs.append(seq)
                    
    # Check IP IDs for ASCII
    text_ip = ""
    for idx in ip_ids:
        # IP ID is 16 bit
        high = (idx >> 8) & 0xFF
        low = idx & 0xFF
        if 32 <= high <= 126: text_ip += chr(high)
        if 32 <= low <= 126: text_ip += chr(low)
        
    print("ASCII in IP IDs:")
    print(text_ip[:200])
    if 'donotecho' in text_ip.lower():
        print("FOUND FLAG IN IP IDs!")
        
    # Check TCP Seq numbers for ASCII
    text_tcp = ""
    for seq in tcp_seqs:
        # Seq is 32 bit
        b1 = (seq >> 24) & 0xFF
        b2 = (seq >> 16) & 0xFF
        b3 = (seq >> 8) & 0xFF
        b4 = seq & 0xFF
        if 32 <= b1 <= 126: text_tcp += chr(b1)
        if 32 <= b2 <= 126: text_tcp += chr(b2)
        if 32 <= b3 <= 126: text_tcp += chr(b3)
        if 32 <= b4 <= 126: text_tcp += chr(b4)
        
    print("ASCII in TCP Seqs:")
    print(text_tcp[:200])
    if 'donotecho' in text_tcp.lower():
        print("FOUND FLAG IN TCP SEQS!")

if __name__ == "__main__":
    extract_invisible()
