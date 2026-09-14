import struct

def render_font_decrypted():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    offset = 24
    
    SCADA = "192.168.100.20"
    
    # Extract all registers by unit
    from collections import defaultdict
    reg_map = defaultdict(dict)
    requests = {}
    
    while offset < len(data) - 16:
        incl_len = struct.unpack(endian + 'I', data[offset+8:offset+12])[0]
        pkt = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(pkt) > 54 and struct.unpack('>H', pkt[12:14])[0] == 0x0800:
            ip = pkt[14:]
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
                                for i in range(0, bc, 2):
                                    if i + 1 < bc:
                                        val = struct.unpack('>H', reg_bytes[i:i+2])[0]
                                        reg_map[uid][start_reg + i//2] = val
                                        
    grid = [[" " for _ in range(16 * 40)] for _ in range(16)]
    
    atk_key = bytes([115, 44, 38, 29, 33, 114, 44])
    
    for uid, regs in reg_map.items():
        # Build payload for unit
        sorted_addrs = sorted(regs.keys())
        payload_bytes = bytearray()
        for addr in sorted_addrs:
            val = regs[addr]
            payload_bytes.append((val >> 8) & 0xFF)
            payload_bytes.append(val & 0xFF)
            
        # XOR
        for i in range(len(payload_bytes)):
            payload_bytes[i] ^= atk_key[i % len(atk_key)]
            
        # Parse decrypted payload as coords
        for i in range(0, len(payload_bytes), 2):
            if i + 1 < len(payload_bytes):
                char_idx = payload_bytes[i]
                pixel_idx = payload_bytes[i+1]
                
                if char_idx < 40:
                    py = pixel_idx // 16
                    px = pixel_idx % 16
                    global_x = char_idx * 16 + px
                    if py < 16 and global_x < 16 * 40:
                        grid[py][global_x] = "█"
                        
    with open('flag_font_decrypted.txt', 'w', encoding='utf-8') as f:
        for row in grid:
            line = "".join(row)
            f.write(line + "\n")
            print(line)

if __name__ == "__main__":
    render_font_decrypted()
