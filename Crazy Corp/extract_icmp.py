import struct

def extract_icmp():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    snaplen = struct.unpack(f'{endian}I', data[16:20])[0]
    offset = 24
    
    icmp_data = bytearray()
    
    while offset < len(data) - 16:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', data[offset:offset+16])
        if incl_len > snaplen or incl_len > len(data) - offset - 16: break
        raw = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(raw) >= 14:
            eth_type = struct.unpack('>H', raw[12:14])[0]
            if eth_type == 0x0800: # IPv4
                ip = raw[14:]
                if len(ip) >= 20:
                    proto = ip[9]
                    if proto == 1: # ICMP
                        ihl = (ip[0] & 0xF) * 4
                        icmp = ip[ihl:]
                        if len(icmp) >= 8:
                            type_ = icmp[0]
                            code = icmp[1]
                            # Echo Request (8) or Echo Reply (0)
                            if type_ == 8 or type_ == 0:
                                payload = icmp[8:]
                                icmp_data.extend(payload)
                                
    with open('icmp_flag.txt', 'wb') as f:
        f.write(icmp_data)
        
    print(f"Extracted {len(icmp_data)} bytes of ICMP payload.")
    
    # Try printing as ASCII
    try:
        text = icmp_data.decode('utf-8', errors='ignore')
        print("Text found in ICMP:")
        print(text)
    except:
        pass

if __name__ == "__main__":
    extract_icmp()
