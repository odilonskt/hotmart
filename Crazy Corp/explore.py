import struct
with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
magic = struct.unpack('<I', data[0:4])[0]
endian = '<' if magic == 0xA1B2C3D4 else '>'
offset = 24
protos = {}
ports = set()
while offset < len(data) - 16:
    incl_len = struct.unpack(endian + 'I', data[offset+8:offset+12])[0]
    pkt = data[offset+16:offset+16+incl_len]
    offset += 16 + incl_len
    if len(pkt) > 34 and struct.unpack('>H', pkt[12:14])[0] == 0x0800:
        ip = pkt[14:]
        proto = ip[9]
        protos[proto] = protos.get(proto, 0) + 1
        ihl = (ip[0] & 0xF) * 4
        if proto in (6, 17) and len(ip) >= ihl + 4:
            src_port = struct.unpack('>H', ip[ihl:ihl+2])[0]
            dst_port = struct.unpack('>H', ip[ihl+2:ihl+4])[0]
            ports.add(src_port)
            ports.add(dst_port)
print('Protocols (IP):', protos)
print('Ports:', sorted(list(ports)))
