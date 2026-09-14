import struct
from collections import Counter

def analyze_pcap():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    snaplen = struct.unpack(f'{endian}I', data[16:20])[0]
    offset = 24
    
    protocols = Counter()
    ports = Counter()
    macs = set()
    
    while offset < len(data) - 16:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', data[offset:offset+16])
        if incl_len > snaplen or incl_len > len(data) - offset - 16: break
        raw = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(raw) >= 14:
            eth_type = struct.unpack('>H', raw[12:14])[0]
            macs.add(raw[0:6].hex())
            macs.add(raw[6:12].hex())
            
            if eth_type == 0x0800: # IPv4
                ip = raw[14:]
                if len(ip) >= 20:
                    proto = ip[9]
                    protocols[proto] += 1
                    ihl = (ip[0] & 0xF) * 4
                    transport = ip[ihl:]
                    if proto == 6 and len(transport) >= 4: # TCP
                        src = struct.unpack('>H', transport[0:2])[0]
                        dst = struct.unpack('>H', transport[2:4])[0]
                        ports[src] += 1
                        ports[dst] += 1
                    elif proto == 17 and len(transport) >= 4: # UDP
                        src = struct.unpack('>H', transport[0:2])[0]
                        dst = struct.unpack('>H', transport[2:4])[0]
                        ports[src] += 1
                        ports[dst] += 1

    with open('pcap_analysis.txt', 'w') as f:
        f.write("Protocols:\n")
        for p, c in protocols.most_common():
            f.write(f"  Proto {p}: {c} pkts\n")
        f.write("\nPorts:\n")
        for p, c in ports.most_common():
            f.write(f"  Port {p}: {c} pkts\n")
        f.write(f"\nTotal MACs: {len(macs)}\n")
        
    print("Analysis saved to pcap_analysis.txt")

if __name__ == "__main__":
    analyze_pcap()
