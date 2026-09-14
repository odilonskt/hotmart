import struct

def find_best_image():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    offset = 24
    
    SCADA = "192.168.100.20"
    raw_pixels = set()
    
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
                                        high = (val >> 8) & 0xFF
                                        low = val & 0xFF
                                        raw_pixels.add((low, high)) # Assuming X=low, Y=high
                                        
    print(f"Loaded {len(raw_pixels)} pixels.")
    
    best_score = -1
    best_kx = 0
    best_ky = 0
    
    for kx in range(256):
        for ky in range(256):
            score = 0
            # To make it fast, just decode a subset or use a fast check
            # Create a set of the mapped pixels
            mapped = {(x ^ kx, y ^ ky) for x, y in raw_pixels}
            
            # Count adjacencies
            for x, y in mapped:
                if (x+1, y) in mapped: score += 1
                if (x, y+1) in mapped: score += 1
                
            if score > best_score:
                best_score = score
                best_kx = kx
                best_ky = ky
                print(f"New best: KX={kx:02X}, KY={ky:02X}, Score={score}")
                
    print(f"Final best: KX={best_kx:02X}, KY={best_ky:02X} with Score={best_score}")
    
    # Save the best image
    mapped = {(x ^ best_kx, y ^ best_ky) for x, y in raw_pixels}
    max_x = max(p[0] for p in mapped) if mapped else 0
    max_y = max(p[1] for p in mapped) if mapped else 0
    
    with open('decrypted_image.txt', 'w', encoding='utf-8') as f:
        for y in range(max_y + 1):
            line = "".join("██" if (x, y) in mapped else "  " for x in range(max_x + 1))
            f.write(line + "\n")
            
    print("Saved to decrypted_image.txt")

if __name__ == "__main__":
    find_best_image()
