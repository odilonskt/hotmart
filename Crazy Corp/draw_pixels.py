import struct
import os

def draw_image():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    offset = 24
    
    SCADA = "192.168.100.20"
    pixels = set()
    
    while offset < len(data) - 16:
        incl_len = struct.unpack(endian + 'I', data[offset+8:offset+12])[0]
        pkt = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(pkt) > 54 and struct.unpack('>H', pkt[12:14])[0] == 0x0800:
            ip = pkt[14:]
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
                    
                    if dst_ip == SCADA and src_port == 502 and len(payload) >= 8:
                        fc = payload[7]
                        if fc == 3 and len(payload) >= 9:
                            bc = payload[8]
                            if len(payload) >= 9 + bc:
                                reg_bytes = payload[9:9+bc]
                                for i in range(0, bc, 2):
                                    if i + 1 < bc:
                                        val = struct.unpack('>H', reg_bytes[i:i+2])[0]
                                        high = (val >> 8) & 0xFF
                                        low = val & 0xFF
                                        pixels.add((low, high)) # X=low, Y=high
                                        
    if not pixels:
        print("No pixels found!")
        return
        
    max_x = max(p[0] for p in pixels)
    max_y = max(p[1] for p in pixels)
    
    print(f"Image size: {max_x+1} x {max_y+1}")
    
    with open('flag_image.txt', 'w', encoding='utf-8') as f:
        for y in range(max_y + 1):
            line = ""
            for x in range(max_x + 1):
                if (x, y) in pixels:
                    line += "██"
                else:
                    line += "  "
            f.write(line + "\n")
            
    print("Saved to flag_image.txt")

if __name__ == "__main__":
    draw_image()
