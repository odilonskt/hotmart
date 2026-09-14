import struct
from collections import defaultdict

def draw_bits():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    offset = 24
    
    SCADA = "192.168.100.20"
    reg_map = defaultdict(dict)
    requests = {}
    
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
                                start_reg = requests.get(tid, -1)
                                if dst_ip == SCADA and start_reg >= 0:
                                    for i in range(0, bc, 2):
                                        if i + 1 < bc:
                                            val = struct.unpack('>H', reg_bytes[i:i+2])[0]
                                            reg_map[uid][start_reg + i//2] = val
                                            
    for uid, regs in reg_map.items():
        if len(regs) < 10: continue
        print(f"Unit {uid} has {len(regs)} registers.")
        
        # Sort by register address
        sorted_addrs = sorted(regs.keys())
        bits = []
        for addr in sorted_addrs:
            val = regs[addr]
            # Convert to 16 bits
            for b in range(16):
                bits.append((val >> (15 - b)) & 1)
                
        print(f"Unit {uid} has {len(bits)} bits.")
        
        # Try widths
        widths = [40, 50, 64, 80, 100, 120, 128, 160, 200, 256]
        for w in widths:
            if w > len(bits): continue
            out = f"--- Unit {uid} Width {w} ---\n"
            for i in range(0, len(bits), w):
                row = bits[i:i+w]
                if len(row) < w: break
                out += "".join("██" if bit else "  " for bit in row) + "\n"
            
            with open(f"unit{uid}_bits_{w}.txt", "w", encoding="utf-8") as f:
                f.write(out)
                
    print("Saved bit images.")

if __name__ == "__main__":
    draw_bits()
