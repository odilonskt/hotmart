import struct

def extract_rgb_lsb():
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

    # Order by timestamp
    responses.sort()
    
    bits = []
    for ts, uid, sreg, values in responses:
        for val in values:
            # RGB565 format: RRRRR GGGGGG BBBBB
            # Bit indices (0 is LSB of B):
            # B: 0-4
            # G: 5-10
            # R: 11-15
            b_lsb = (val >> 0) & 1
            g_lsb = (val >> 5) & 1
            r_lsb = (val >> 11) & 1
            
            # Which order? RGB or BGR? Let's append all 3 and try.
            # Usually R, G, B order
            bits.extend([r_lsb, g_lsb, b_lsb])
            
    print(f"Total extracted RGB LSB bits: {len(bits)}")
    
    for offset in range(8):
        byte_arr = []
        for i in range(offset, len(bits) - 7, 8):
            b = 0
            for j in range(8):
                b = (b << 1) | bits[i+j]
            byte_arr.append(b)
        text = "".join(chr(b) if 32 <= b <= 126 else '.' for b in byte_arr)
        if 'donotecho' in text.lower() or 'donotecho' in text:
            print(f"FOUND! MSB RGB Order, offset {offset}: {text}")
            return
            
    bits_bgr = []
    for ts, uid, sreg, values in responses:
        for val in values:
            b_lsb = (val >> 0) & 1
            g_lsb = (val >> 5) & 1
            r_lsb = (val >> 11) & 1
            bits_bgr.extend([b_lsb, g_lsb, r_lsb])
            
    for offset in range(8):
        byte_arr = []
        for i in range(offset, len(bits_bgr) - 7, 8):
            b = 0
            for j in range(8):
                b = (b << 1) | bits_bgr[i+j]
            byte_arr.append(b)
        text = "".join(chr(b) if 32 <= b <= 126 else '.' for b in byte_arr)
        if 'donotecho' in text.lower() or 'donotecho' in text:
            print(f"FOUND! MSB BGR Order, offset {offset}: {text}")
            return

    print("Trying just printing the start of MSB RGB offset 0:")
    byte_arr = []
    for i in range(0, min(len(bits) - 7, 800), 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i+j]
        byte_arr.append(b)
    print("".join(chr(b) if 32 <= b <= 126 else '.' for b in byte_arr))

if __name__ == "__main__":
    extract_rgb_lsb()
