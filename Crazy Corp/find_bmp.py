import struct

def find_bmp():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    snaplen = struct.unpack(f'{endian}I', data[16:20])[0]
    offset = 24
    
    SCADA = "192.168.100.20"
    requests = {}
    
    payloads = bytearray()
    
    while offset < len(data) - 16:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', data[offset:offset+16])
        if incl_len > snaplen or incl_len > len(data) - offset - 16: break
        raw = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(raw) > 54 and struct.unpack('>H', raw[12:14])[0] == 0x0800:
            ip = raw[14:]
            if len(ip) > 20 and ip[9] == 6:
                dst_ip = '.'.join(str(b) for b in ip[16:20])
                ihl = (ip[0] & 0xF) * 4
                tcp = ip[ihl:]
                if len(tcp) >= 20:
                    src_port = struct.unpack('>H', tcp[0:2])[0]
                    dst_port = struct.unpack('>H', tcp[2:4])[0]
                    doff = ((tcp[12] >> 4) & 0xF) * 4
                    payload = tcp[doff:]
                    
                    if len(payload) >= 8:
                        tid = struct.unpack('>H', payload[0:2])[0]
                        uid = payload[6]
                        fc = payload[7]
                        
                        if dst_port == 502 and fc == 3 and len(payload) >= 12:
                            requests[tid] = struct.unpack('>H', payload[8:10])[0]
                            
                        elif src_port == 502 and fc == 3 and len(payload) >= 9:
                            bc = payload[8]
                            start_reg = requests.get(tid, -1)
                            if dst_ip == SCADA and start_reg >= 0 and len(payload) >= 9 + bc:
                                reg_bytes = payload[9:9+bc]
                                payloads.extend(reg_bytes)

    idx = payloads.find(b'BM')
    if idx != -1:
        print(f"Found 'BM' at index {idx}!")
        with open("extracted.bmp", "wb") as f:
            f.write(payloads[idx:])
        print("Saved to extracted.bmp")
    else:
        print("No BMP found.")

    idx = payloads.find(b'\x89PNG')
    if idx != -1:
        print(f"Found 'PNG' at index {idx}!")
        with open("extracted.png", "wb") as f:
            f.write(payloads[idx:])
        print("Saved to extracted.png")
    else:
        print("No PNG found.")

if __name__ == "__main__":
    find_bmp()
