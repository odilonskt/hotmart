#!/usr/bin/env python3
"""
INDUSTRIAL MELTDOWN - Focused Decoder
Extrai e decodifica tráfego Modbus focando no atacante (192.168.100.200)
e nos dados dos registradores.
"""

import struct
import os
import base64

def read_pcap(filepath):
    """Lê PCAP e retorna lista de pacotes parseados."""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    magic = struct.unpack('<I', data[0:4])[0]
    if magic == 0xA1B2C3D4:
        endian = '<'
    elif magic == 0xD4C3B2A1:
        endian = '>'
    else:
        print(f"Formato não suportado: 0x{magic:08X}")
        return []
    
    snaplen = struct.unpack(f'{endian}I', data[16:20])[0]
    
    offset = 24
    packets = []
    while offset < len(data) - 16:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', data[offset:offset+16])
        if incl_len > snaplen or incl_len > len(data) - offset - 16:
            break
        pkt_data = data[offset+16:offset+16+incl_len]
        packets.append({'ts': ts_sec + ts_usec/1e6, 'data': pkt_data, 'len': incl_len})
        offset += 16 + incl_len
    
    return packets


def parse_packet(pkt_data):
    """Parse Ethernet -> IP -> TCP e retorna info estruturada."""
    if len(pkt_data) < 54:  # Min Ethernet(14) + IP(20) + TCP(20)
        return None
    
    # Ethernet
    ethertype = struct.unpack('>H', pkt_data[12:14])[0]
    if ethertype != 0x0800:  # Só IPv4
        return None
    
    # IP
    ip_data = pkt_data[14:]
    if len(ip_data) < 20:
        return None
    
    ihl = (ip_data[0] & 0xF) * 4
    protocol = ip_data[9]
    src_ip = '.'.join(str(b) for b in ip_data[12:16])
    dst_ip = '.'.join(str(b) for b in ip_data[16:20])
    
    if protocol != 6:  # Só TCP
        return {'src_ip': src_ip, 'dst_ip': dst_ip, 'protocol': protocol}
    
    # TCP
    tcp_data = ip_data[ihl:]
    if len(tcp_data) < 20:
        return None
    
    src_port = struct.unpack('>H', tcp_data[0:2])[0]
    dst_port = struct.unpack('>H', tcp_data[2:4])[0]
    data_offset = ((tcp_data[12] >> 4) & 0xF) * 4
    flags = tcp_data[13]
    
    payload = tcp_data[data_offset:]
    
    return {
        'src_ip': src_ip, 'dst_ip': dst_ip,
        'src_port': src_port, 'dst_port': dst_port,
        'flags': flags, 'payload': payload,
        'protocol': 6,
        'src_mac': ':'.join(f'{b:02x}' for b in pkt_data[6:12]),
        'dst_mac': ':'.join(f'{b:02x}' for b in pkt_data[0:6]),
    }


def parse_modbus(payload):
    """Parse Modbus TCP e retorna info estruturada."""
    if len(payload) < 8:
        return None
    
    trans_id = struct.unpack('>H', payload[0:2])[0]
    proto_id = struct.unpack('>H', payload[2:4])[0]
    length = struct.unpack('>H', payload[4:6])[0]
    unit_id = payload[6]
    fc = payload[7]
    mb_data = payload[8:]
    
    result = {
        'trans_id': trans_id,
        'unit_id': unit_id,
        'fc': fc,
        'raw_data': mb_data,
    }
    
    # Parse FC 3 request (Read Holding Registers)
    if fc == 3 and len(mb_data) == 4:
        result['type'] = 'read_request'
        result['start_reg'] = struct.unpack('>H', mb_data[0:2])[0]
        result['num_regs'] = struct.unpack('>H', mb_data[2:4])[0]
    
    # Parse FC 3 response (Read Holding Registers)
    elif fc == 3 and len(mb_data) >= 1:
        byte_count = mb_data[0]
        if len(mb_data) >= 1 + byte_count and byte_count > 0:
            result['type'] = 'read_response'
            result['byte_count'] = byte_count
            result['reg_bytes'] = mb_data[1:1+byte_count]
            values = []
            for i in range(0, byte_count, 2):
                if i + 1 < byte_count:
                    values.append(struct.unpack('>H', mb_data[1+i:1+i+2])[0])
            result['values'] = values
        else:
            result['type'] = 'read_request'
            result['start_reg'] = struct.unpack('>H', mb_data[0:2])[0] if len(mb_data) >= 2 else 0
            result['num_regs'] = struct.unpack('>H', mb_data[2:4])[0] if len(mb_data) >= 4 else 0
    
    # Parse FC 6 (Write Single Register)
    elif fc == 6:
        result['type'] = 'write_single'
        if len(mb_data) >= 4:
            result['reg_addr'] = struct.unpack('>H', mb_data[0:2])[0]
            result['reg_val'] = struct.unpack('>H', mb_data[2:4])[0]
    
    # Parse FC 16 (Write Multiple Registers)
    elif fc == 16:
        result['type'] = 'write_multiple'
        if len(mb_data) >= 5:
            result['start_reg'] = struct.unpack('>H', mb_data[0:2])[0]
            result['num_regs'] = struct.unpack('>H', mb_data[2:4])[0]
            result['byte_count'] = mb_data[4]
            values = []
            for i in range(5, min(len(mb_data), 5 + mb_data[4]), 2):
                if i + 1 <= len(mb_data):
                    values.append(struct.unpack('>H', mb_data[i:i+2])[0])
            result['values'] = values
    
    # FC 43 (Read Device Identification)
    elif fc == 0x2B:
        result['type'] = 'device_id'
    
    # FC 5 (Write Single Coil)
    elif fc == 5:
        result['type'] = 'write_coil'
        if len(mb_data) >= 4:
            result['coil_addr'] = struct.unpack('>H', mb_data[0:2])[0]
            result['coil_val'] = struct.unpack('>H', mb_data[2:4])[0]
    
    else:
        result['type'] = 'unknown'
    
    return result


def values_to_ascii(values):
    """Converte lista de valores de registradores para ASCII."""
    chars = []
    for v in values:
        hi = (v >> 8) & 0xFF
        lo = v & 0xFF
        if 0x20 <= hi <= 0x7E:
            chars.append(chr(hi))
        if 0x20 <= lo <= 0x7E:
            chars.append(chr(lo))
    return ''.join(chars)


def values_to_bytes(values):
    """Converte lista de valores de registradores para bytes."""
    result = bytearray()
    for v in values:
        result.append((v >> 8) & 0xFF)
        result.append(v & 0xFF)
    return bytes(result)


def try_xor_decode(data, keys=None):
    """Tenta decodificar dados com diferentes chaves XOR."""
    if keys is None:
        keys = list(range(256))
    
    results = []
    for key in keys:
        decoded = bytes([b ^ key for b in data])
        try:
            text = decoded.decode('ascii')
            printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
            ratio = printable / len(text) if text else 0
            if ratio > 0.7:
                results.append((key, text, ratio))
        except:
            pass
    
    results.sort(key=lambda x: -x[2])
    return results


def main():
    filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "industrial_meltdown.pcap")
    
    print("=" * 80)
    print(" INDUSTRIAL MELTDOWN - FOCUSED MODBUS DECODER")
    print("=" * 80)
    
    packets = read_pcap(filepath)
    print(f"\nTotal de pacotes: {len(packets)}")
    
    # Classificar pacotes
    attacker_ip = "192.168.100.200"
    scada_ip = "192.168.100.20"
    plc_ips = {"192.168.100.101", "192.168.100.102", "192.168.100.103", "192.168.100.110"}
    
    attacker_packets = []
    normal_packets = []
    attacker_responses = []
    normal_responses = []
    all_modbus = []
    write_operations = []
    
    for i, pkt in enumerate(packets):
        parsed = parse_packet(pkt['data'])
        if parsed is None or parsed.get('protocol') != 6:
            continue
        
        payload = parsed.get('payload', b'')
        if not payload or len(payload) < 8:
            continue
        
        src_port = parsed.get('src_port', 0)
        dst_port = parsed.get('dst_port', 0)
        
        if dst_port != 502 and src_port != 502:
            continue
        
        mb = parse_modbus(payload)
        if mb is None:
            continue
        
        mb['pkt_num'] = i
        mb['src_ip'] = parsed['src_ip']
        mb['dst_ip'] = parsed['dst_ip']
        mb['src_port'] = src_port
        mb['dst_port'] = dst_port
        mb['ts'] = pkt['ts']
        all_modbus.append(mb)
        
        # Classificar
        if parsed['src_ip'] == attacker_ip:
            attacker_packets.append(mb)
        elif parsed['dst_ip'] == attacker_ip:
            attacker_responses.append(mb)
        elif parsed['src_ip'] == scada_ip:
            normal_packets.append(mb)
        elif parsed['src_ip'] in plc_ips and parsed['dst_ip'] == scada_ip:
            normal_responses.append(mb)
        
        # Coletar operações de escrita
        if mb.get('type') in ['write_single', 'write_multiple', 'write_coil']:
            write_operations.append(mb)
    
    # ====================================================
    # SEÇÃO 1: TRÁFEGO DO ATACANTE
    # ====================================================
    print(f"\n{'='*80}")
    print(f" SEÇÃO 1: TRÁFEGO DO ATACANTE ({attacker_ip})")
    print(f"{'='*80}")
    print(f"\n  Requests do atacante: {len(attacker_packets)}")
    print(f"  Responses para atacante: {len(attacker_responses)}")
    
    for mb in attacker_packets:
        fc_names = {3: "Read Regs", 6: "Write Reg", 16: "Write Multi", 0x2B: "Device ID", 5: "Write Coil"}
        fc_name = fc_names.get(mb['fc'], f"FC{mb['fc']}")
        
        print(f"\n  [Pkt#{mb['pkt_num']}] {mb['src_ip']}:{mb['src_port']} -> {mb['dst_ip']}:{mb['dst_port']}")
        print(f"    TransID: 0x{mb['trans_id']:04X} | Unit: {mb['unit_id']} | FC: {mb['fc']} ({fc_name})")
        
        if mb['type'] == 'read_request':
            print(f"    READ registers {mb.get('start_reg', '?')}-{mb.get('start_reg', 0)+mb.get('num_regs', 0)-1} (count={mb.get('num_regs', '?')})")
        elif mb['type'] == 'write_single':
            print(f"    WRITE register {mb.get('reg_addr', '?')} = {mb.get('reg_val', '?')} (0x{mb.get('reg_val', 0):04X})")
            val = mb.get('reg_val', 0)
            chars = ""
            hi = (val >> 8) & 0xFF
            lo = val & 0xFF
            if 0x20 <= hi <= 0x7E: chars += chr(hi)
            if 0x20 <= lo <= 0x7E: chars += chr(lo)
            if chars: print(f"    ASCII: '{chars}'")
        elif mb['type'] == 'write_multiple':
            print(f"    WRITE registers {mb.get('start_reg', '?')}-{mb.get('start_reg', 0)+mb.get('num_regs', 0)-1}")
            print(f"    Values: {mb.get('values', [])}")
            ascii_str = values_to_ascii(mb.get('values', []))
            if ascii_str: print(f"    ASCII: '{ascii_str}'")
        elif mb['type'] == 'write_coil':
            print(f"    WRITE COIL {mb.get('coil_addr', '?')} = {mb.get('coil_val', '?')}")
        elif mb['type'] == 'device_id':
            print(f"    DEVICE IDENTIFICATION (reconnaissance)")
        
        print(f"    Raw: {mb['raw_data'].hex()}")
    
    # Responses para o atacante
    print(f"\n  --- Respostas para o atacante ---")
    attacker_reg_values = {}  # reg_addr -> value
    
    for mb in attacker_responses:
        print(f"\n  [Pkt#{mb['pkt_num']}] {mb['src_ip']}:{mb['src_port']} -> {mb['dst_ip']}:{mb['dst_port']}")
        print(f"    TransID: 0x{mb['trans_id']:04X} | Unit: {mb['unit_id']} | FC: {mb['fc']}")
        
        if mb.get('type') == 'read_response':
            print(f"    Values: {mb.get('values', [])}")
            print(f"    Bytes: {mb.get('reg_bytes', b'').hex()}")
            ascii_str = values_to_ascii(mb.get('values', []))
            if ascii_str: print(f"    ASCII: '{ascii_str}'")
        
        print(f"    Raw: {mb['raw_data'].hex()}")
    
    # ====================================================
    # SEÇÃO 2: OPERAÇÕES DE ESCRITA (TODAS)
    # ====================================================
    print(f"\n{'='*80}")
    print(f" SEÇÃO 2: TODAS AS OPERAÇÕES DE ESCRITA")
    print(f"{'='*80}")
    print(f"\n  Total de escritas: {len(write_operations)}")
    
    write_values_by_src = {}
    
    for mb in write_operations:
        src = mb['src_ip']
        if src not in write_values_by_src:
            write_values_by_src[src] = []
        
        print(f"\n  [Pkt#{mb['pkt_num']}] {mb['src_ip']} -> {mb['dst_ip']} (Unit {mb['unit_id']})")
        print(f"    TransID: 0x{mb['trans_id']:04X} | FC: {mb['fc']}")
        
        if mb['type'] == 'write_single':
            val = mb.get('reg_val', 0)
            reg = mb.get('reg_addr', 0)
            print(f"    Register {reg} = {val} (0x{val:04X})")
            write_values_by_src[src].append((reg, val))
            hi = (val >> 8) & 0xFF
            lo = val & 0xFF
            chars = ""
            if 0x20 <= hi <= 0x7E: chars += chr(hi)
            if 0x20 <= lo <= 0x7E: chars += chr(lo)
            if chars: print(f"    ASCII: '{chars}'")
        elif mb['type'] == 'write_multiple':
            start = mb.get('start_reg', 0)
            values = mb.get('values', [])
            print(f"    Registers {start}-{start+len(values)-1}: {values}")
            for j, v in enumerate(values):
                write_values_by_src[src].append((start + j, v))
            ascii_str = values_to_ascii(values)
            if ascii_str: print(f"    ASCII: '{ascii_str}'")
            raw_bytes = values_to_bytes(values)
            print(f"    Raw bytes: {raw_bytes.hex()}")
        elif mb['type'] == 'write_coil':
            addr = mb.get('coil_addr', 0)
            val = mb.get('coil_val', 0)
            print(f"    Coil {addr} = {'ON' if val == 0xFF00 else 'OFF' if val == 0 else hex(val)}")
        
        print(f"    Raw: {mb['raw_data'].hex()}")
    
    # ====================================================
    # SEÇÃO 3: ANÁLISE DOS VALORES DOS REGISTROS (Respostas)
    # ====================================================
    print(f"\n{'='*80}")
    print(f" SEÇÃO 3: DADOS DOS REGISTRADORES (Respostas FC3)")
    print(f"{'='*80}")
    
    # Agrupar por Unit ID e registros
    responses_by_unit = {}
    for mb in all_modbus:
        if mb.get('type') == 'read_response' and mb.get('values'):
            unit = mb['unit_id']
            if unit not in responses_by_unit:
                responses_by_unit[unit] = []
            responses_by_unit[unit].append(mb)
    
    all_register_bytes = bytearray()
    
    for unit in sorted(responses_by_unit.keys()):
        responses = responses_by_unit[unit]
        print(f"\n  --- Unit {unit} ({len(responses)} respostas) ---")
        
        unit_bytes = bytearray()
        for mb in responses:
            values = mb.get('values', [])
            reg_bytes = mb.get('reg_bytes', b'')
            
            if reg_bytes:
                unit_bytes.extend(reg_bytes)
                all_register_bytes.extend(reg_bytes)
            
            # Tentar ASCII
            ascii_str = values_to_ascii(values)
            if len(ascii_str) > 2:
                print(f"    [Pkt#{mb['pkt_num']}] ASCII: '{ascii_str}' | hex: {reg_bytes.hex()}")
        
        # Tentar decodificar bytes acumulados do unit
        if unit_bytes:
            print(f"\n  [Unit {unit}] Todos os bytes acumulados ({len(unit_bytes)} bytes):")
            print(f"    Hex: {unit_bytes.hex()}")
            
            # XOR brute force
            xor_results = try_xor_decode(unit_bytes)
            if xor_results:
                print(f"    Melhor XOR decode (top 3):")
                for key, text, ratio in xor_results[:3]:
                    print(f"      Key 0x{key:02X}: '{text[:80]}' (printable: {ratio:.0%})")
    
    # ====================================================
    # SEÇÃO 4: TENTATIVAS DE DECODIFICAÇÃO GLOBAL
    # ====================================================
    print(f"\n{'='*80}")
    print(f" SEÇÃO 4: DECODIFICAÇÃO GLOBAL")
    print(f"{'='*80}")
    
    # Todos os bytes de resposta concatenados
    print(f"\n  Total de bytes de registros: {len(all_register_bytes)}")
    print(f"  Hex: {all_register_bytes.hex()[:200]}...")
    
    # XOR com várias chaves
    print(f"\n  --- XOR brute force (todos os bytes) ---")
    xor_all = try_xor_decode(all_register_bytes)
    if xor_all:
        for key, text, ratio in xor_all[:5]:
            print(f"  Key 0x{key:02X} ({ratio:.0%} printable): '{text[:100]}'")
    
    # Extrair apenas os valores de escrita do atacante
    if attacker_ip in write_values_by_src:
        print(f"\n  --- Valores escritos pelo atacante ---")
        atk_writes = write_values_by_src[attacker_ip]
        atk_writes.sort(key=lambda x: x[0])
        
        print(f"  Registros (ordenados): {atk_writes}")
        
        atk_bytes = bytearray()
        for reg, val in atk_writes:
            atk_bytes.append((val >> 8) & 0xFF)
            atk_bytes.append(val & 0xFF)
        
        print(f"  Bytes: {atk_bytes.hex()}")
        print(f"  ASCII direto: {atk_bytes.decode('ascii', errors='replace')}")
        
        # XOR
        xor_atk = try_xor_decode(atk_bytes)
        if xor_atk:
            for key, text, ratio in xor_atk[:5]:
                print(f"  XOR 0x{key:02X}: '{text}' ({ratio:.0%})")
        
        # Base64
        try:
            b64 = base64.b64decode(atk_bytes)
            print(f"  Base64: {b64.decode('utf-8', errors='replace')}")
        except:
            pass
    
    # ====================================================
    # SEÇÃO 5: TransID do atacante como dados
    # ====================================================
    print(f"\n{'='*80}")
    print(f" SEÇÃO 5: TransIDs do atacante")
    print(f"{'='*80}")
    
    if attacker_packets:
        trans_ids = [mb['trans_id'] for mb in attacker_packets]
        print(f"  TransIDs: {[f'0x{t:04X}' for t in trans_ids]}")
        
        trans_bytes = bytearray()
        for t in trans_ids:
            trans_bytes.append((t >> 8) & 0xFF)
            trans_bytes.append(t & 0xFF)
        
        print(f"  Bytes: {trans_bytes.hex()}")
        print(f"  ASCII: {trans_bytes.decode('ascii', errors='replace')}")
        
        # Só byte baixo
        low_bytes = bytearray([t & 0xFF for t in trans_ids])
        print(f"  Low bytes: {low_bytes.hex()}")
        print(f"  Low ASCII: {low_bytes.decode('ascii', errors='replace')}")
        
        # Só byte alto
        high_bytes = bytearray([(t >> 8) & 0xFF for t in trans_ids])
        print(f"  High bytes: {high_bytes.hex()}")
        print(f"  High ASCII: {high_bytes.decode('ascii', errors='replace')}")
    
    # ====================================================
    # SEÇÃO 6: Buscar padrões em todos os dados Modbus
    # ====================================================
    print(f"\n{'='*80}")
    print(f" SEÇÃO 6: TODOS OS RAW DATA (por pacote)")
    print(f"{'='*80}")
    
    # Concatenar todos os raw_data dos responses
    all_raw_response = bytearray()
    all_raw_from_plc = bytearray()
    
    for mb in all_modbus:
        if mb.get('type') == 'read_response':
            all_raw_response.extend(mb.get('reg_bytes', b''))
        
        # Dados de PLCs para SCADA
        if mb['src_ip'] in plc_ips and mb['dst_ip'] == scada_ip:
            all_raw_from_plc.extend(mb.get('reg_bytes', b''))
    
    # Tentar decodificar
    print(f"\n  Raw response bytes (PLC -> SCADA): {len(all_raw_from_plc)} bytes")
    
    # Try XOR on just PLC->SCADA data
    print(f"\n  --- XOR brute force (PLC->SCADA) ---")
    xor_plc = try_xor_decode(all_raw_from_plc)
    if xor_plc:
        for key, text, ratio in xor_plc[:5]:
            clean = text.replace('\x00', '').replace('\x01', '').replace('\x02', '')
            print(f"  Key 0x{key:02X} ({ratio:.0%}): '{clean[:120]}'")
    
    # ====================================================
    # SEÇÃO 7: Extrair dados por tipo de registros
    # ====================================================
    print(f"\n{'='*80}")
    print(f" SEÇÃO 7: VALORES POR RANGE DE REGISTROS")
    print(f"{'='*80}")
    
    # Tentar correlacionar requests com responses
    # Para cada request, o response seguinte do mesmo transID deve ter os dados
    pending_reads = {}
    register_map = {}  # (unit, reg_addr) -> value
    
    for mb in all_modbus:
        tid = mb['trans_id']
        
        if mb.get('type') == 'read_request':
            pending_reads[tid] = mb
        elif mb.get('type') == 'read_response' and tid in pending_reads:
            req = pending_reads[tid]
            start_reg = req.get('start_reg', 0)
            unit = mb['unit_id']
            values = mb.get('values', [])
            
            for j, v in enumerate(values):
                register_map[(unit, start_reg + j)] = v
            
            del pending_reads[tid]
    
    # Imprimir mapa de registros organizado
    if register_map:
        units = set(k[0] for k in register_map.keys())
        for unit in sorted(units):
            unit_regs = {k[1]: v for k, v in register_map.items() if k[0] == unit}
            if unit_regs:
                sorted_regs = sorted(unit_regs.items())
                print(f"\n  Unit {unit}:")
                for reg, val in sorted_regs:
                    hi = (val >> 8) & 0xFF
                    lo = val & 0xFF
                    chars = ""
                    if 0x20 <= hi <= 0x7E: chars += chr(hi)
                    if 0x20 <= lo <= 0x7E: chars += chr(lo)
                    char_str = f" '{chars}'" if chars else ""
                    print(f"    Reg {reg:5d} = {val:5d} (0x{val:04X}){char_str}")
    
    # ====================================================
    # SEÇÃO 8: Extração de strings de registro por ranges
    # ====================================================
    print(f"\n{'='*80}")
    print(f" SEÇÃO 8: STRINGS POR RANGE DE REGISTROS")
    print(f"{'='*80}")
    
    if register_map:
        units = set(k[0] for k in register_map.keys())
        for unit in sorted(units):
            unit_regs = {k[1]: v for k, v in register_map.items() if k[0] == unit}
            if not unit_regs:
                continue
            
            # Agrupar por ranges contíguos
            sorted_addrs = sorted(unit_regs.keys())
            ranges = []
            current_range = [sorted_addrs[0]]
            
            for addr in sorted_addrs[1:]:
                if addr == current_range[-1] + 1:
                    current_range.append(addr)
                else:
                    ranges.append(current_range)
                    current_range = [addr]
            ranges.append(current_range)
            
            for r in ranges:
                values = [unit_regs[addr] for addr in r]
                raw_bytes = values_to_bytes(values)
                ascii_str = values_to_ascii(values)
                
                print(f"\n  Unit {unit}, Regs {r[0]}-{r[-1]}:")
                print(f"    Values: {values}")
                print(f"    Hex: {raw_bytes.hex()}")
                if ascii_str:
                    print(f"    ASCII: '{ascii_str}'")
                
                # XOR decode
                xor_results = try_xor_decode(raw_bytes)
                if xor_results:
                    print(f"    Best XOR:")
                    for key, text, ratio in xor_results[:3]:
                        print(f"      0x{key:02X} ({ratio:.0%}): '{text}'")
                
                # Base64 tentativa
                try:
                    b64 = base64.b64decode(raw_bytes)
                    if len(b64) > 0:
                        text = b64.decode('utf-8', errors='replace')
                        printable = sum(1 for c in text if c.isprintable()) / len(text) if text else 0
                        if printable > 0.5:
                            print(f"    Base64: '{text}'")
                except:
                    pass
    
    print(f"\n{'='*80}")
    print(" ANÁLISE COMPLETA")
    print(f"{'='*80}")


if __name__ == "__main__":
    main()
