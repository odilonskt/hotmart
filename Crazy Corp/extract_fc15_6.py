import struct

def extract_fc15_fc6():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    snaplen = struct.unpack(f'{endian}I', data[16:20])[0]
    offset = 24
    
    print("--- ATLANTEAN WHISPERS: FC 15 and FC 6 ---")
    
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
                    
                    if len(payload) >= 8 and (src_port == 502 or dst_port == 502):
                        tid = struct.unpack('>H', payload[0:2])[0]
                        uid = payload[6]
                        fc = payload[7]
                        
                        if fc == 15 and len(payload) >= 13: # Write Multiple Coils
                            start_addr = struct.unpack('>H', payload[8:10])[0]
                            qty = struct.unpack('>H', payload[10:12])[0]
                            byte_cnt = payload[12]
                            if len(payload) >= 13 + byte_cnt:
                                coil_data = payload[13:13+byte_cnt]
                                print(f"FC 15 (Write Coils) | UID: {uid} | Addr: {start_addr} | Qty: {qty} | Data: {coil_data.hex()}")
                                
                        elif fc == 6 and len(payload) >= 12: # Write Single Register
                            addr = struct.unpack('>H', payload[8:10])[0]
                            val = struct.unpack('>H', payload[10:12])[0]
                            print(f"FC 6 (Write Reg)    | UID: {uid} | Addr: {addr} | Val: {val} (0x{val:04x})")

if __name__ == "__main__":
    extract_fc15_fc6()
