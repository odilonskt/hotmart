import struct
from collections import defaultdict

def extract_lsb():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    snaplen = struct.unpack(f'{endian}I', data[16:20])[0]
    offset = 24
    
    SCADA = "192.168.100.20"
    requests = {}
    responses = []
    
    pkt_num = 0
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
                            start_reg = struct.unpack('>H', payload[8:10])[0]
                            requests[tid] = start_reg
                            
                        elif src_port == 502 and fc == 3 and len(payload) >= 9:
                            bc = payload[8]
                            if len(payload) >= 9 + bc:
                                reg_bytes = payload[9:9+bc]
                                values = []
                                for i in range(0, bc, 2):
                                    if i + 1 < bc:
                                        values.append(struct.unpack('>H', reg_bytes[i:i+2])[0])
                                start_reg = requests.get(tid, -1)
                                if dst_ip == SCADA and start_reg >= 0:
                                    responses.append((ts_sec + ts_usec / 1e6, uid, start_reg, values))
        pkt_num += 1

    # Strategy 1: Order by timestamp
    responses.sort()
    
    bits = []
    for ts, uid, sreg, values in responses:
        for val in values:
            bits.append(val & 1)
            
    print(f"--- TIMESTAMP ORDER ---")
    for offset in range(8):
        byte_arr = []
        for i in range(offset, len(bits) - 7, 8):
            b = 0
            for j in range(8): b = (b << 1) | bits[i+j]
            byte_arr.append(b)
        print(f"MSB[{offset}]: " + "".join(chr(b) if 32 <= b <= 126 else '.' for b in byte_arr))
        
        byte_arr = []
        for i in range(offset, len(bits) - 7, 8):
            b = 0
            for j in range(8): b |= (bits[i+j] << j)
            byte_arr.append(b)
        print(f"LSB[{offset}]: " + "".join(chr(b) if 32 <= b <= 126 else '.' for b in byte_arr))
        
    # Strategy 2: Order by Unit, then Register
    reg_map = defaultdict(dict)
    for ts, uid, sreg, values in responses:
        for i, val in enumerate(values):
            reg_map[uid][sreg + i] = val
            
    bits = []
    for uid in sorted(reg_map.keys()):
        for sreg in sorted(reg_map[uid].keys()):
            bits.append(reg_map[uid][sreg] & 1)
            
    print(f"\n--- UNIT+REG ORDER ---")
    for offset in range(8):
        byte_arr = []
        for i in range(offset, len(bits) - 7, 8):
            b = 0
            for j in range(8): b = (b << 1) | bits[i+j]
            byte_arr.append(b)
        print(f"MSB[{offset}]: " + "".join(chr(b) if 32 <= b <= 126 else '.' for b in byte_arr))
        
        byte_arr = []
        for i in range(offset, len(bits) - 7, 8):
            b = 0
            for j in range(8): b |= (bits[i+j] << j)
            byte_arr.append(b)
        print(f"LSB[{offset}]: " + "".join(chr(b) if 32 <= b <= 126 else '.' for b in byte_arr))

if __name__ == "__main__":
    extract_lsb()
