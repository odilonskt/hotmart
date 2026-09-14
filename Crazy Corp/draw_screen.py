import struct
from collections import defaultdict

def draw_screen():
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
                src_ip = '.'.join(str(b) for b in ip[12:16])
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
                            num_regs = struct.unpack('>H', payload[10:12])[0]
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
                                    responses.append({'uid': uid, 'start_reg': start_reg, 'values': values})
        pkt_num += 1
        
    reg_map = defaultdict(dict)
    for resp in responses:
        uid = resp['uid']
        sreg = resp['start_reg']
        for i, val in enumerate(resp['values']):
            reg_map[uid][sreg + i] = val
            
    # Unit 1 has 500 registers!
    if 1 in reg_map:
        regs = reg_map[1]
        print(f"Unit 1 has {len(regs)} registers.")
        if len(regs) >= 500:
            # Let's try widths: 20, 25, 50
            for width in [20, 25, 50]:
                print(f"--- Width {width} ---")
                height = 500 // width
                with open(f"screen_{width}.txt", "w", encoding="utf-8") as f:
                    for y in range(height):
                        line = ""
                        for x in range(width):
                            addr = y * width + x
                            val = regs.get(addr, 0)
                            # Let's say 0 is space, anything else is block
                            # Or maybe specific color
                            if val == 0: line += "  "
                            elif val == 65535: line += "██"
                            else:
                                # if it's RGB565, let's just output block if not 0
                                line += "██"
                        f.write(line + "\n")
                        print(line)
                print()

if __name__ == "__main__":
    draw_screen()
