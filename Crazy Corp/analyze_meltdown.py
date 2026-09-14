#!/usr/bin/env python3
"""
Análise inicial do PCAP - Extrai informações brutas do arquivo
"""
import struct
import sys
import os

def read_pcap_raw(filepath):
    """Lê um arquivo PCAP e extrai informações dos pacotes."""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print(f"Tamanho total: {len(data)} bytes")
    print(f"Primeiros 24 bytes (hex): {data[:24].hex()}")
    
    # PCAP Global Header (24 bytes)
    magic = struct.unpack('<I', data[0:4])[0]
    print(f"\nMagic number: 0x{magic:08X}")
    
    if magic == 0xA1B2C3D4:
        print("Formato: PCAP (Little Endian)")
        endian = '<'
    elif magic == 0xD4C3B2A1:
        print("Formato: PCAP (Big Endian)")
        endian = '>'
    elif magic == 0x0A0D0D0A:
        print("Formato: PCAPNG")
        endian = '<'
        analyze_pcapng(data)
        return
    else:
        print(f"Formato desconhecido! Magic: 0x{magic:08X}")
        # Tenta procurar strings no arquivo todo
        print("\n--- Procurando strings ASCII no arquivo ---")
        find_strings(data)
        return
    
    version_major, version_minor = struct.unpack(f'{endian}HH', data[4:8])
    thiszone, sigfigs = struct.unpack(f'{endian}iI', data[8:16])
    snaplen, network = struct.unpack(f'{endian}II', data[16:24])
    
    print(f"Versão: {version_major}.{version_minor}")
    print(f"Snaplen: {snaplen}")
    print(f"Link-layer type: {network}")
    
    link_types = {0: "NULL/Loopback", 1: "Ethernet", 101: "Raw IP", 113: "Linux SLL", 228: "Raw IPv4", 229: "Raw IPv6"}
    print(f"Link-layer name: {link_types.get(network, 'Unknown')}")
    
    # Parse packets
    offset = 24
    pkt_num = 0
    packets = []
    
    while offset < len(data) - 16:
        # Packet header: ts_sec(4), ts_usec(4), incl_len(4), orig_len(4)
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', data[offset:offset+16])
        
        if incl_len > snaplen or incl_len > len(data) - offset - 16:
            print(f"\n[!] Pacote {pkt_num} inválido: incl_len={incl_len}, restante={len(data)-offset-16}")
            break
        
        pkt_data = data[offset+16:offset+16+incl_len]
        packets.append({
            'num': pkt_num,
            'ts_sec': ts_sec,
            'ts_usec': ts_usec,
            'incl_len': incl_len,
            'orig_len': orig_len,
            'data': pkt_data,
        })
        
        pkt_num += 1
        offset += 16 + incl_len
    
    print(f"\nTotal de pacotes: {pkt_num}")
    
    # Analisar cada pacote
    print(f"\n{'='*80}")
    print("ANÁLISE DOS PACOTES")
    print(f"{'='*80}")
    
    for pkt in packets:
        print(f"\n--- Pacote #{pkt['num']} | {pkt['incl_len']} bytes | ts={pkt['ts_sec']}.{pkt['ts_usec']} ---")
        pkt_data = pkt['data']
        
        if network == 1:  # Ethernet
            parse_ethernet(pkt_data, pkt['num'])
        elif network == 101:  # Raw IP
            parse_ip(pkt_data, pkt['num'])
        else:
            print(f"  Raw hex: {pkt_data.hex()}")
            find_strings_in_data(pkt_data, f"Pkt#{pkt['num']}")
    
    # Busca global de strings
    print(f"\n{'='*80}")
    print("BUSCA GLOBAL DE STRINGS")
    print(f"{'='*80}")
    find_strings(data)
    
    # Busca por padrões de encoding
    print(f"\n{'='*80}")
    print("BUSCA POR DADOS CODIFICADOS")
    print(f"{'='*80}")
    find_encoded_data(data)


def analyze_pcapng(data):
    """Analisa arquivo PCAPNG."""
    print("\n--- Formato PCAPNG detectado ---")
    
    offset = 0
    block_num = 0
    all_packet_data = bytearray()
    
    while offset < len(data) - 12:
        # Block Header: Type(4) + TotalLength(4)
        block_type = struct.unpack('<I', data[offset:offset+4])[0]
        block_len = struct.unpack('<I', data[offset+4:offset+8])[0]
        
        if block_len < 12 or block_len > len(data) - offset:
            print(f"  [!] Bloco inválido em offset {offset}")
            break
        
        block_data = data[offset+8:offset+block_len-4]
        
        block_names = {
            0x0A0D0D0A: "Section Header Block",
            0x00000001: "Interface Description Block",
            0x00000006: "Enhanced Packet Block",
            0x00000003: "Simple Packet Block",
            0x00000005: "Interface Statistics Block",
        }
        
        bname = block_names.get(block_type, f"Unknown (0x{block_type:08X})")
        print(f"\n  Block #{block_num}: {bname} | len={block_len}")
        
        if block_type == 0x0A0D0D0A:  # SHB
            # SHB body: byte_order_magic(4) + major(2) + minor(2) + section_length(8)
            if len(block_data) >= 16:
                bom = struct.unpack('<I', block_data[0:4])[0]
                major, minor = struct.unpack('<HH', block_data[4:8])
                print(f"    Byte order magic: 0x{bom:08X}")
                print(f"    Version: {major}.{minor}")
                # Options
                if len(block_data) > 16:
                    parse_pcapng_options(block_data[16:])
        
        elif block_type == 0x00000001:  # IDB
            if len(block_data) >= 8:
                link_type = struct.unpack('<H', block_data[0:2])[0]
                snap_len = struct.unpack('<I', block_data[4:8])[0]
                link_names = {0: "NULL", 1: "Ethernet", 101: "Raw IP", 113: "Linux SLL", 147: "USER0"}
                print(f"    Link type: {link_type} ({link_names.get(link_type, 'Unknown')})")
                print(f"    Snap length: {snap_len}")
                if len(block_data) > 8:
                    parse_pcapng_options(block_data[8:])
        
        elif block_type == 0x00000006:  # EPB
            if len(block_data) >= 20:
                iface_id = struct.unpack('<I', block_data[0:4])[0]
                ts_high, ts_low = struct.unpack('<II', block_data[4:12])
                cap_len = struct.unpack('<I', block_data[12:16])[0]
                orig_len = struct.unpack('<I', block_data[16:20])[0]
                pkt_bytes = block_data[20:20+cap_len]
                
                print(f"    Interface: {iface_id} | Captured: {cap_len} | Original: {orig_len}")
                print(f"    Packet hex: {pkt_bytes.hex()[:120]}...")
                
                all_packet_data.extend(pkt_bytes)
                
                # Try parsing as ethernet or raw
                if cap_len > 14:
                    parse_ethernet(pkt_bytes, block_num)
                
                find_strings_in_data(pkt_bytes, f"EPB#{block_num}")
        
        elif block_type == 0x00000003:  # SPB
            if len(block_data) >= 4:
                orig_len = struct.unpack('<I', block_data[0:4])[0]
                pkt_bytes = block_data[4:]
                print(f"    Original length: {orig_len}")
                print(f"    Packet hex: {pkt_bytes.hex()[:120]}...")
                all_packet_data.extend(pkt_bytes)
                find_strings_in_data(pkt_bytes, f"SPB#{block_num}")
        
        block_num += 1
        offset += block_len
    
    print(f"\nTotal de blocos: {block_num}")
    
    # Busca global
    print(f"\n{'='*80}")
    print("BUSCA GLOBAL DE STRINGS NO ARQUIVO")
    print(f"{'='*80}")
    find_strings(data)
    
    print(f"\n{'='*80}")
    print("BUSCA POR DADOS CODIFICADOS")
    print(f"{'='*80}")
    find_encoded_data(data)


def parse_pcapng_options(data):
    """Parse PCAPNG options."""
    offset = 0
    while offset < len(data) - 4:
        opt_code = struct.unpack('<H', data[offset:offset+2])[0]
        opt_len = struct.unpack('<H', data[offset+2:offset+4])[0]
        
        if opt_code == 0:  # end of options
            break
        
        opt_val = data[offset+4:offset+4+opt_len]
        
        # Try to decode as string
        try:
            opt_str = opt_val.decode('utf-8', errors='replace')
            print(f"    Option {opt_code}: {opt_str}")
        except:
            print(f"    Option {opt_code}: {opt_val.hex()}")
        
        # Pad to 4-byte boundary
        padded_len = opt_len + (4 - opt_len % 4) % 4
        offset += 4 + padded_len


def parse_ethernet(data, pkt_num):
    """Parse Ethernet frame."""
    if len(data) < 14:
        print(f"  [!] Frame muito curto: {len(data)} bytes")
        return
    
    dst_mac = ':'.join(f'{b:02x}' for b in data[0:6])
    src_mac = ':'.join(f'{b:02x}' for b in data[6:12])
    ethertype = struct.unpack('>H', data[12:14])[0]
    
    ether_names = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "VLAN"}
    print(f"  Ethernet: {src_mac} -> {dst_mac} | Type: 0x{ethertype:04X} ({ether_names.get(ethertype, '?')})")
    
    if ethertype == 0x0800:
        parse_ip(data[14:], pkt_num)
    elif ethertype == 0x0806:
        print(f"  ARP packet")
    else:
        print(f"  Payload hex: {data[14:].hex()[:80]}")
        find_strings_in_data(data[14:], f"Eth#{pkt_num}")


def parse_ip(data, pkt_num):
    """Parse IPv4 packet."""
    if len(data) < 20:
        return
    
    version_ihl = data[0]
    version = (version_ihl >> 4) & 0xF
    ihl = (version_ihl & 0xF) * 4
    total_len = struct.unpack('>H', data[2:4])[0]
    protocol = data[9]
    src_ip = '.'.join(str(b) for b in data[12:16])
    dst_ip = '.'.join(str(b) for b in data[16:20])
    
    proto_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    print(f"  IP: {src_ip} -> {dst_ip} | Proto: {protocol} ({proto_names.get(protocol, '?')})")
    
    payload = data[ihl:]
    
    if protocol == 6:  # TCP
        parse_tcp(payload, pkt_num, src_ip, dst_ip)
    elif protocol == 17:  # UDP
        parse_udp(payload, pkt_num, src_ip, dst_ip)
    elif protocol == 1:  # ICMP
        parse_icmp(payload, pkt_num)
    else:
        print(f"  Payload hex: {payload.hex()[:80]}")
        find_strings_in_data(payload, f"IP#{pkt_num}")


def parse_tcp(data, pkt_num, src_ip, dst_ip):
    """Parse TCP segment."""
    if len(data) < 20:
        return
    
    src_port = struct.unpack('>H', data[0:2])[0]
    dst_port = struct.unpack('>H', data[2:4])[0]
    seq = struct.unpack('>I', data[4:8])[0]
    ack = struct.unpack('>I', data[8:12])[0]
    data_offset = ((data[12] >> 4) & 0xF) * 4
    flags = data[13]
    
    flag_str = ""
    if flags & 0x02: flag_str += "SYN "
    if flags & 0x10: flag_str += "ACK "
    if flags & 0x01: flag_str += "FIN "
    if flags & 0x04: flag_str += "RST "
    if flags & 0x08: flag_str += "PSH "
    
    print(f"  TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flag_str.strip()} | Seq: {seq}")
    
    # Known ports
    port_names = {80: "HTTP", 443: "HTTPS", 502: "Modbus", 102: "S7comm", 
                  44818: "EtherNet/IP", 20000: "DNP3", 47808: "BACnet",
                  4840: "OPC-UA", 1883: "MQTT", 8883: "MQTT-TLS"}
    
    if src_port in port_names:
        print(f"  Protocol hint: {port_names[src_port]}")
    if dst_port in port_names:
        print(f"  Protocol hint: {port_names[dst_port]}")
    
    tcp_payload = data[data_offset:]
    if tcp_payload:
        print(f"  TCP Payload ({len(tcp_payload)} bytes): {tcp_payload.hex()[:100]}")
        
        # Modbus TCP (port 502)
        if src_port == 502 or dst_port == 502:
            parse_modbus(tcp_payload, pkt_num)
        
        # S7comm (port 102)
        if src_port == 102 or dst_port == 102:
            print(f"  [S7comm] Raw: {tcp_payload.hex()}")
        
        find_strings_in_data(tcp_payload, f"TCP#{pkt_num}:{src_port}->{dst_port}")


def parse_udp(data, pkt_num, src_ip, dst_ip):
    """Parse UDP datagram."""
    if len(data) < 8:
        return
    
    src_port = struct.unpack('>H', data[0:2])[0]
    dst_port = struct.unpack('>H', data[2:4])[0]
    length = struct.unpack('>H', data[4:6])[0]
    
    print(f"  UDP: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Len: {length}")
    
    udp_payload = data[8:]
    if udp_payload:
        print(f"  UDP Payload ({len(udp_payload)} bytes): {udp_payload.hex()[:100]}")
        
        # DNS (port 53)
        if src_port == 53 or dst_port == 53:
            parse_dns(udp_payload, pkt_num)
        
        find_strings_in_data(udp_payload, f"UDP#{pkt_num}:{src_port}->{dst_port}")


def parse_icmp(data, pkt_num):
    """Parse ICMP packet."""
    if len(data) < 8:
        return
    
    icmp_type = data[0]
    icmp_code = data[1]
    
    type_names = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
    print(f"  ICMP: Type={icmp_type} ({type_names.get(icmp_type, '?')}) Code={icmp_code}")
    
    if len(data) > 8:
        payload = data[8:]
        print(f"  ICMP Payload ({len(payload)} bytes): {payload.hex()[:100]}")
        find_strings_in_data(payload, f"ICMP#{pkt_num}")


def parse_modbus(data, pkt_num):
    """Parse Modbus TCP."""
    if len(data) < 8:
        return
    
    # MBAP Header
    trans_id = struct.unpack('>H', data[0:2])[0]
    proto_id = struct.unpack('>H', data[2:4])[0]
    length = struct.unpack('>H', data[4:6])[0]
    unit_id = data[6]
    fc = data[7]
    
    fc_names = {
        1: "Read Coils", 2: "Read Discrete Inputs",
        3: "Read Holding Registers", 4: "Read Input Registers",
        5: "Write Single Coil", 6: "Write Single Register",
        15: "Write Multiple Coils", 16: "Write Multiple Registers",
        43: "Read Device Identification",
    }
    
    print(f"  [MODBUS] TransID: {trans_id} | Unit: {unit_id} | FC: {fc} ({fc_names.get(fc, 'Unknown')})")
    
    modbus_data = data[8:]
    if fc == 3 or fc == 4:  # Read registers
        if len(modbus_data) >= 4:
            start_reg = struct.unpack('>H', modbus_data[0:2])[0]
            num_regs = struct.unpack('>H', modbus_data[2:4])[0]
            print(f"  [MODBUS] Read from register {start_reg}, count={num_regs}")
        elif len(modbus_data) >= 1:
            byte_count = modbus_data[0]
            reg_values = []
            for i in range(1, min(len(modbus_data), byte_count + 1), 2):
                if i + 1 < len(modbus_data):
                    val = struct.unpack('>H', modbus_data[i:i+2])[0]
                    reg_values.append(val)
            print(f"  [MODBUS] Response: byte_count={byte_count}, values={reg_values}")
            # Try interpreting register values as ASCII
            ascii_chars = []
            for v in reg_values:
                hi = (v >> 8) & 0xFF
                lo = v & 0xFF
                if 0x20 <= hi <= 0x7E:
                    ascii_chars.append(chr(hi))
                if 0x20 <= lo <= 0x7E:
                    ascii_chars.append(chr(lo))
            if ascii_chars:
                print(f"  [MODBUS] Registers as ASCII: {''.join(ascii_chars)}")
    
    elif fc == 6:  # Write single register
        if len(modbus_data) >= 4:
            reg_addr = struct.unpack('>H', modbus_data[0:2])[0]
            reg_val = struct.unpack('>H', modbus_data[2:4])[0]
            print(f"  [MODBUS] Write register {reg_addr} = {reg_val} (0x{reg_val:04X})")
            # ASCII interpretation
            hi = (reg_val >> 8) & 0xFF
            lo = reg_val & 0xFF
            chars = ""
            if 0x20 <= hi <= 0x7E: chars += chr(hi)
            if 0x20 <= lo <= 0x7E: chars += chr(lo)
            if chars:
                print(f"  [MODBUS] Value as ASCII: '{chars}'")
    
    elif fc == 16:  # Write multiple registers
        if len(modbus_data) >= 5:
            start_reg = struct.unpack('>H', modbus_data[0:2])[0]
            num_regs = struct.unpack('>H', modbus_data[2:4])[0]
            byte_count = modbus_data[4]
            values = []
            for i in range(5, min(len(modbus_data), 5 + byte_count), 2):
                if i + 1 <= len(modbus_data):
                    val = struct.unpack('>H', modbus_data[i:i+2])[0]
                    values.append(val)
            print(f"  [MODBUS] Write registers {start_reg}-{start_reg+num_regs-1}: {values}")
            # ASCII
            ascii_str = ""
            for v in values:
                hi = (v >> 8) & 0xFF
                lo = v & 0xFF
                if 0x20 <= hi <= 0x7E: ascii_str += chr(hi)
                if 0x20 <= lo <= 0x7E: ascii_str += chr(lo)
            if ascii_str:
                print(f"  [MODBUS] Values as ASCII: '{ascii_str}'")
    
    if modbus_data:
        print(f"  [MODBUS] Raw data: {modbus_data.hex()}")


def parse_dns(data, pkt_num):
    """Parse DNS packet."""
    if len(data) < 12:
        return
    
    tx_id = struct.unpack('>H', data[0:2])[0]
    flags = struct.unpack('>H', data[2:4])[0]
    qr = (flags >> 15) & 1
    qdcount = struct.unpack('>H', data[4:6])[0]
    ancount = struct.unpack('>H', data[6:8])[0]
    
    direction = "Response" if qr else "Query"
    print(f"  [DNS] {direction} | TxID: 0x{tx_id:04X} | Questions: {qdcount} | Answers: {ancount}")
    
    # Parse question section
    offset = 12
    for _ in range(qdcount):
        name, offset = parse_dns_name(data, offset)
        if offset + 4 <= len(data):
            qtype = struct.unpack('>H', data[offset:offset+2])[0]
            qclass = struct.unpack('>H', data[offset+2:offset+4])[0]
            type_names = {1: "A", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
            print(f"  [DNS] Query: {name} (Type: {type_names.get(qtype, str(qtype))})")
            offset += 4
    
    # Parse answer section
    for _ in range(ancount):
        if offset >= len(data):
            break
        name, offset = parse_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype = struct.unpack('>H', data[offset:offset+2])[0]
        rclass = struct.unpack('>H', data[offset+2:offset+4])[0]
        ttl = struct.unpack('>I', data[offset+4:offset+8])[0]
        rdlength = struct.unpack('>H', data[offset+8:offset+10])[0]
        rdata = data[offset+10:offset+10+rdlength]
        offset += 10 + rdlength
        
        if rtype == 1 and rdlength == 4:  # A record
            ip = '.'.join(str(b) for b in rdata)
            print(f"  [DNS] Answer: {name} -> {ip}")
        elif rtype == 16:  # TXT record
            txt = rdata[1:1+rdata[0]].decode('utf-8', errors='replace') if rdata else ""
            print(f"  [DNS] TXT: {name} -> {txt}")
        else:
            print(f"  [DNS] Answer: {name} type={rtype} -> {rdata.hex()}")


def parse_dns_name(data, offset):
    """Parse DNS name with compression support."""
    name_parts = []
    jumps = 0
    original_offset = offset
    jumped = False
    
    while offset < len(data):
        length = data[offset]
        if length == 0:
            if not jumped:
                original_offset = offset + 1
            break
        elif (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = struct.unpack('>H', data[offset:offset+2])[0] & 0x3FFF
            if not jumped:
                original_offset = offset + 2
            jumped = True
            offset = pointer
            jumps += 1
            if jumps > 10:
                break
        else:
            offset += 1
            name_parts.append(data[offset:offset+length].decode('utf-8', errors='replace'))
            offset += length
    
    return '.'.join(name_parts), original_offset


def find_strings(data, min_len=4):
    """Find ASCII strings in binary data."""
    import re
    strings = re.findall(b'[\x20-\x7e]{' + str(min_len).encode() + b',}', data)
    
    if strings:
        print(f"\n  Strings encontradas ({len(strings)} total):")
        for s in strings:
            decoded = s.decode('ascii', errors='replace')
            # Highlight potential flags and interesting strings
            interesting = any(kw in decoded.lower() for kw in [
                'flag', 'ctf', 'key', 'secret', 'password', 'donotecho', 'meltdown',
                'base64', 'xor', 'encrypted', 'hidden', 'decode', 'hack',
                '{', '}', 'shadow', 'modbus', 'scada', 'plc', 'token',
            ])
            marker = " <<<< INTERESTING!" if interesting else ""
            if len(decoded) > 6 or interesting:
                print(f"    \"{decoded}\"{marker}")


def find_strings_in_data(data, label="", min_len=4):
    """Find ASCII strings in a specific data chunk."""
    import re
    strings = re.findall(b'[\x20-\x7e]{' + str(min_len).encode() + b',}', data)
    for s in strings:
        decoded = s.decode('ascii', errors='replace')
        if len(decoded) > 4:
            interesting = any(kw in decoded.lower() for kw in [
                'flag', 'ctf', 'key', 'secret', 'donotecho', 'meltdown',
                '{', '}', 'shadow', 'scada', 'plc', 'hidden',
            ])
            marker = " <<<< FLAG/KEY?" if interesting else ""
            print(f"  [{label}] String: \"{decoded}\"{marker}")


def find_encoded_data(data):
    """Search for base64, hex-encoded data, and other encodings."""
    import re
    import base64
    
    # Search for base64 patterns
    print("\n[Base64 candidates]")
    b64_pattern = re.findall(b'[A-Za-z0-9+/]{16,}={0,2}', data)
    for b64 in b64_pattern:
        try:
            decoded = base64.b64decode(b64)
            text = decoded.decode('utf-8', errors='replace')
            if any(c.isprintable() for c in text) and len(text) > 3:
                print(f"  B64: {b64[:60].decode('ascii', errors='replace')}...")
                print(f"    -> Decoded: {text[:100]}")
        except:
            pass
    
    # Search for hex-encoded strings
    print("\n[Hex-encoded candidates]")
    hex_pattern = re.findall(b'(?:[0-9a-fA-F]{2}[: ]?){8,}', data)
    for h in hex_pattern[:10]:
        hex_clean = h.decode('ascii', errors='replace').replace(':', '').replace(' ', '')
        try:
            decoded = bytes.fromhex(hex_clean).decode('ascii', errors='replace')
            if all(c.isprintable() or c in '\n\r\t' for c in decoded):
                print(f"  Hex: {h[:60].decode('ascii', errors='replace')}...")
                print(f"    -> Decoded: {decoded[:100]}")
        except:
            pass
    
    # XOR brute force on interesting-looking data segments
    print("\n[XOR brute force on data segments]")
    # Look for data segments that could be XOR'd text
    for key in [0x42, 0xFF, 0x13, 0x37, 0xAA, 0x55, 0x0F, 0xF0]:
        test_data = bytes([b ^ key for b in data[:200]])
        strings = re.findall(b'[\x20-\x7e]{8,}', test_data)
        for s in strings:
            decoded = s.decode('ascii', errors='replace')
            if any(kw in decoded.lower() for kw in ['flag', 'ctf', 'key', 'donotecho', '{', '}', 'meltdown']):
                print(f"  XOR key 0x{key:02X}: \"{decoded}\"")


if __name__ == "__main__":
    filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "industrial_meltdown.pcap")
    if not os.path.exists(filepath):
        print(f"Arquivo não encontrado: {filepath}")
        sys.exit(1)
    
    print(f"{'='*80}")
    print(f" INDUSTRIAL MELTDOWN - PCAP ANALYZER")
    print(f" Arquivo: {filepath}")
    print(f" Tamanho: {os.path.getsize(filepath)} bytes")
    print(f"{'='*80}")
    
    read_pcap_raw(filepath)
