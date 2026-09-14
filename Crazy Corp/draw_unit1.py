import struct

def draw_unit1_image():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    offset = 24
    
    SCADA = "192.168.100.20"
    
    # Store registers for Unit 1
    regs = {}
    
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
                            # Assuming sequential responses, we need the start_reg
                            # But we don't have the request here.
                            pass

    # Since we need start_reg, it's easier to use a simplified parser
    # Let's extract values by assuming they are ordered in the packet
    # Or just use the responses we know are 0-499
    
if __name__ == "__main__":
    draw_unit1_image()
