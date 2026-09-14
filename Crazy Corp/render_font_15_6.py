import struct

def render_font_dimensions():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    offset = 24
    
    SCADA = "192.168.100.20"
    
    pixels = []
    
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
                    doff = ((tcp[12] >> 4) & 0xF) * 4
                    payload = tcp[doff:]
                    
                    if dst_ip == SCADA and src_port == 502 and len(payload) >= 8:
                        fc = payload[7]
                        if fc == 3 and len(payload) >= 9:
                            bc = payload[8]
                            if len(payload) >= 9 + bc:
                                reg_bytes = payload[9:9+bc]
                                for i in range(0, bc, 2):
                                    if i + 1 < bc:
                                        val = struct.unpack('>H', reg_bytes[i:i+2])[0]
                                        char_idx = (val >> 8) & 0xFF
                                        pixel_idx = val & 0xFF
                                        pixels.append((char_idx, pixel_idx))
                                        
    # Try 15x6 (W=15, H=6)
    grid1 = [[" " for _ in range(15 * 45)] for _ in range(15)]
    for char_idx, pixel_idx in pixels:
        if char_idx < 45:
            py = pixel_idx // 15
            px = pixel_idx % 15
            if py < 15 and px < 15:
                grid1[py][char_idx * 15 + px] = "█"
                
    with open('font_15x15.txt', 'w', encoding='utf-8') as f:
        for row in grid1: f.write("".join(row) + "\n")
        
    # Try 6x15 (W=6, H=15)
    grid2 = [[" " for _ in range(6 * 45)] for _ in range(15)]
    for char_idx, pixel_idx in pixels:
        if char_idx < 45:
            py = pixel_idx // 6
            px = pixel_idx % 6
            if py < 15 and px < 6:
                grid2[py][char_idx * 6 + px] = "█"
                
    with open('font_6x15.txt', 'w', encoding='utf-8') as f:
        for row in grid2: f.write("".join(row) + "\n")
        
    print("Created font_15x15.txt and font_6x15.txt")

if __name__ == "__main__":
    render_font_dimensions()
