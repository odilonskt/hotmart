import struct

def check_fragments():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    snaplen = struct.unpack(f'{endian}I', data[16:20])[0]
    offset = 24
    
    fragments = []
    
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
                    flags_frag = struct.unpack('>H', ip[6:8])[0]
                    mf = (flags_frag >> 13) & 1
                    frag_offset = flags_frag & 0x1FFF
                    if mf == 1 or frag_offset > 0:
                        fragments.append(raw)
                        
    print(f"Total fragmented packets: {len(fragments)}")
    if fragments:
        print("FRAGMENTS FOUND!")

if __name__ == "__main__":
    check_fragments()
