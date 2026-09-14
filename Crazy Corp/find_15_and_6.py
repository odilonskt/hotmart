import struct

def find_15_and_6():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    offset = 24
    
    SCADA = "192.168.100.20"
    
    found_15 = []
    found_6 = []
    
    while offset < len(data) - 16:
        incl_len = struct.unpack(endian + 'I', data[offset+8:offset+12])[0]
        pkt = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(pkt) > 54 and struct.unpack('>H', pkt[12:14])[0] == 0x0800:
            ip = pkt[14:]
            if len(ip) > 20 and ip[9] == 6:
                src_ip = '.'.join(str(b) for b in ip[12:16])
                ihl = (ip[0] & 0xF) * 4
                tcp = ip[ihl:]
                if len(tcp) >= 20:
                    dst_port = struct.unpack('>H', tcp[2:4])[0]
                    doff = ((tcp[12] >> 4) & 0xF) * 4
                    payload = tcp[doff:]
                    
                    # Look for Write commands (from SCADA to Units)
                    if src_ip == SCADA and dst_port == 502 and len(payload) >= 8:
                        fc = payload[7]
                        if fc == 15 and len(payload) >= 13:
                            addr = struct.unpack('>H', payload[8:10])[0]
                            qty = struct.unpack('>H', payload[10:12])[0]
                            byte_cnt = payload[12]
                            vals = payload[13:13+byte_cnt]
                            found_15.append((addr, qty, vals))
                        elif fc == 6 and len(payload) >= 12:
                            addr = struct.unpack('>H', payload[8:10])[0]
                            val = struct.unpack('>H', payload[10:12])[0]
                            found_6.append((addr, val))
                            
    with open('15_and_6_found.txt', 'w') as f:
        f.write(f"Found {len(found_15)} FC 15 (Write Multiple Coils) packets:\n")
        for addr, qty, vals in found_15:
            f.write(f"Addr: {addr}, Qty: {qty}, Vals: {vals.hex()} ({vals})\n")
        
        f.write(f"\nFound {len(found_6)} FC 6 (Write Single Register) packets:\n")
        for addr, val in found_6:
            f.write(f"Addr: {addr}, Val: {val}\n")
            
    print("Results saved to 15_and_6_found.txt")

if __name__ == "__main__":
    find_15_and_6()
