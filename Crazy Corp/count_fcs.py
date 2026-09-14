import struct

def count_fcs():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    offset = 24
    
    fcs = {}
    
    while offset < len(data) - 16:
        incl_len = struct.unpack(endian + 'I', data[offset+8:offset+12])[0]
        pkt = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(pkt) > 54 and struct.unpack('>H', pkt[12:14])[0] == 0x0800:
            ip = pkt[14:]
            if len(ip) > 20 and ip[9] == 6:
                ihl = (ip[0] & 0xF) * 4
                tcp = ip[ihl:]
                if len(tcp) >= 20:
                    doff = ((tcp[12] >> 4) & 0xF) * 4
                    payload = tcp[doff:]
                    if len(payload) >= 8:
                        fc = payload[7]
                        fcs[fc] = fcs.get(fc, 0) + 1
                        
    print("Function Codes used:")
    for fc, count in sorted(fcs.items()):
        print(f"  FC {fc}: {count} packets")

if __name__ == "__main__":
    count_fcs()
