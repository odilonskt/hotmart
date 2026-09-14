import struct
from collections import Counter

def count_fcs():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    snaplen = struct.unpack(f'{endian}I', data[16:20])[0]
    offset = 24
    
    fcs = Counter()
    
    while offset < len(data) - 16:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', data[offset:offset+16])
        if incl_len > snaplen or incl_len > len(data) - offset - 16: break
        raw = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(raw) > 54 and struct.unpack('>H', raw[12:14])[0] == 0x0800:
            ip = raw[14:]
            if len(ip) > 20 and ip[9] == 6:
                ihl = (ip[0] & 0xF) * 4
                tcp = ip[ihl:]
                if len(tcp) >= 20:
                    src_port = struct.unpack('>H', tcp[0:2])[0]
                    dst_port = struct.unpack('>H', tcp[2:4])[0]
                    doff = ((tcp[12] >> 4) & 0xF) * 4
                    payload = tcp[doff:]
                    
                    if len(payload) >= 8 and (src_port == 502 or dst_port == 502):
                        fc = payload[7]
                        fcs[fc] += 1
                        
    print("Modbus Function Codes found:")
    for fc, count in fcs.most_common():
        print(f"FC {fc}: {count} times")

if __name__ == "__main__":
    count_fcs()
