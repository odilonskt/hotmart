import struct

def split_images():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    offset = 24
    
    SCADA = "192.168.100.20"
    pixels_per_ip = {}
    
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
                                        if src_ip not in pixels_per_ip:
                                            pixels_per_ip[src_ip] = set()
                                        pixels_per_ip[src_ip].add((low, high)) # X=low, Y=high
                                        
    print(f"Found pixels for {len(pixels_per_ip)} IPs:")
    for ip, pixels in pixels_per_ip.items():
        print(f"  {ip}: {len(pixels)} pixels")
        
    # Overlay all IPs
    all_ips = list(pixels_per_ip.keys())
    if len(all_ips) >= 2:
        ip1, ip2 = all_ips[0], all_ips[1]
        p1 = pixels_per_ip[ip1]
        p2 = pixels_per_ip[ip2]
        
        # visual cryptography usually uses XOR or AND
        # Let's try XOR: pixels in one but not the other
        xored = p1 ^ p2
        
        max_x = max(p[0] for p in xored) if xored else 0
        max_y = max(p[1] for p in xored) if xored else 0
        
        with open('xored_image.txt', 'w', encoding='utf-8') as f:
            for y in range(max_y + 1):
                line = ""
                for x in range(max_x + 1):
                    if (x, y) in xored:
                        line += "██"
                    else:
                        line += "  "
                f.write(line + "\n")
        print("Wrote xored_image.txt")

if __name__ == "__main__":
    split_images()
