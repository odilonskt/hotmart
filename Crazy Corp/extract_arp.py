import struct

def extract_arp():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    snaplen = struct.unpack(f'{endian}I', data[16:20])[0]
    offset = 24
    
    arps = []
    
    while offset < len(data) - 16:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', data[offset:offset+16])
        if incl_len > snaplen or incl_len > len(data) - offset - 16: break
        raw = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(raw) >= 14:
            eth_type = struct.unpack('>H', raw[12:14])[0]
            if eth_type == 0x0806: # ARP
                arps.append(raw)
                
    print(f"Total ARP packets: {len(arps)}")
    
    # Analyze ARP for steganography
    # ARP packet: 
    # HTYPE (2), PTYPE (2), HLEN (1), PLEN (1), OPER (2)
    # SHA (6), SPA (4), THA (6), TPA (4)
    # Total 28 bytes
    
    hidden_data = bytearray()
    
    for i, pkt in enumerate(arps):
        arp_data = pkt[14:]
        if len(arp_data) >= 28:
            # Check if there is padding or hidden data in MAC/IP fields
            # Let's print out the raw ARP data
            print(f"ARP {i}: {arp_data.hex()}")
            
            # The flag might be in the MAC addresses or padding
            # Normal ARP length in ethernet is 46 bytes (14 eth + 28 ARP + 4 padding)
            if len(pkt) > 42:
                padding = pkt[42:]
                hidden_data.extend(padding)

    print("\nHidden Data in ARP padding:")
    print(hidden_data)
    
    # Also check MAC addresses
    mac_text = bytearray()
    for pkt in arps:
        arp_data = pkt[14:]
        if len(arp_data) >= 28:
            sha = arp_data[8:14]
            tha = arp_data[18:24]
            mac_text.extend(sha)
            mac_text.extend(tha)
            
    print("\nMAC Address data text:")
    # Filter printable
    printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in mac_text)
    print(printable)
    
    with open('arp_analysis.txt', 'w') as f:
        f.write(f"Total ARP packets: {len(arps)}\n")
        f.write(f"Padding: {hidden_data}\n")
        f.write(f"MACs: {printable}\n")

if __name__ == "__main__":
    extract_arp()
