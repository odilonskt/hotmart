#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  INDUSTRIAL MELTDOWN - DECODER FINAL                        ║
║  Flag format: donotecho{@lGumA_C0!sa_AqU!}                 ║
║  Charset: a-z, A-Z, 0-9, @, !, _, {, }                     ║
╚══════════════════════════════════════════════════════════════╝
"""

import struct
import os
import re
import base64
from collections import Counter, defaultdict

PREFIX = "donotecho{"
SUFFIX = "}"
FLAG_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@!_{}")

def read_pcap(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    snaplen = struct.unpack(f'{endian}I', data[16:20])[0]
    offset = 24
    packets = []
    pkt_num = 0
    while offset < len(data) - 16:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', data[offset:offset+16])
        if incl_len > snaplen or incl_len > len(data) - offset - 16:
            break
        packets.append({
            'num': pkt_num,
            'ts': ts_sec + ts_usec / 1e6,
            'raw': data[offset+16:offset+16+incl_len]
        })
        pkt_num += 1
        offset += 16 + incl_len
    return packets, data

def parse_ethernet_ip_tcp(raw):
    if len(raw) < 54:
        return None
    if struct.unpack('>H', raw[12:14])[0] != 0x0800:
        return None
    ip = raw[14:]
    if ip[9] != 6:
        return None
    ihl = (ip[0] & 0xF) * 4
    src_ip = '.'.join(str(b) for b in ip[12:16])
    dst_ip = '.'.join(str(b) for b in ip[16:20])
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    src_port = struct.unpack('>H', tcp[0:2])[0]
    dst_port = struct.unpack('>H', tcp[2:4])[0]
    seq = struct.unpack('>I', tcp[4:8])[0]
    doff = ((tcp[12] >> 4) & 0xF) * 4
    payload = tcp[doff:]
    return {
        'src_ip': src_ip, 'dst_ip': dst_ip,
        'src_port': src_port, 'dst_port': dst_port,
        'seq': seq, 'payload': payload,
        'src_mac': raw[6:12].hex(), 'dst_mac': raw[0:6].hex(),
    }

def parse_modbus(payload):
    if len(payload) < 8:
        return None
    tid = struct.unpack('>H', payload[0:2])[0]
    proto = struct.unpack('>H', payload[2:4])[0]
    length = struct.unpack('>H', payload[4:6])[0]
    uid = payload[6]
    fc = payload[7]
    data = payload[8:]
    return {'tid': tid, 'proto': proto, 'length': length, 'uid': uid, 'fc': fc, 'data': data}

def is_flag_char(c):
    return c in FLAG_CHARS

def flag_score(text):
    """Score how likely text is a flag."""
    score = 0
    if text.startswith(PREFIX):
        score += 100
    if text.endswith(SUFFIX):
        score += 50
    flag_ratio = sum(1 for c in text if is_flag_char(c)) / max(len(text), 1)
    score += int(flag_ratio * 50)
    if 'donotecho' in text:
        score += 200
    return score

def main():
    filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "industrial_meltdown.pcap")
    packets, raw_data = read_pcap(filepath)
    print(f"Total pacotes: {len(packets)}")
    
    ATTACKER = "192.168.100.200"
    SCADA = "192.168.100.20"
    
    # ================================================================
    # FASE 1: Extrair TODOS os dados Modbus
    # ================================================================
    requests = {}  # tid -> {start_reg, num_regs, uid, dst_ip, pkt}
    responses = []  # Lista de respostas FC3
    all_modbus = []
    writes = []
    
    for pkt in packets:
        parsed = parse_ethernet_ip_tcp(pkt['raw'])
        if not parsed or not parsed['payload'] or len(parsed['payload']) < 8:
            continue
        mb = parse_modbus(parsed['payload'])
        if not mb:
            continue
        
        mb.update({
            'pkt': pkt['num'], 'ts': pkt['ts'],
            'src_ip': parsed['src_ip'], 'dst_ip': parsed['dst_ip'],
            'src_port': parsed['src_port'], 'dst_port': parsed['dst_port'],
        })
        all_modbus.append(mb)
        
        # FC3 Request (dst_port 502)
        if mb['fc'] == 3 and parsed['dst_port'] == 502 and len(mb['data']) >= 4:
            start_reg = struct.unpack('>H', mb['data'][0:2])[0]
            num_regs = struct.unpack('>H', mb['data'][2:4])[0]
            requests[mb['tid']] = {
                'start_reg': start_reg, 'num_regs': num_regs,
                'uid': mb['uid'], 'pkt': pkt['num'],
                'src_ip': parsed['src_ip'], 'dst_ip': parsed['dst_ip'],
            }
        
        # FC3 Response (src_port 502)
        if mb['fc'] == 3 and parsed['src_port'] == 502 and len(mb['data']) >= 3:
            bc = mb['data'][0]
            if bc >= 2 and len(mb['data']) >= 1 + bc:
                reg_bytes = mb['data'][1:1+bc]
                values = []
                for i in range(0, bc, 2):
                    if i + 1 < bc:
                        values.append(struct.unpack('>H', reg_bytes[i:i+2])[0])
                
                is_atk = (parsed['dst_ip'] == ATTACKER)
                
                # Correlacionar com request pelo TID
                start_reg = -1
                if mb['tid'] in requests:
                    start_reg = requests[mb['tid']]['start_reg']
                
                responses.append({
                    'pkt': pkt['num'], 'ts': pkt['ts'],
                    'uid': mb['uid'], 'tid': mb['tid'],
                    'byte_count': bc, 'reg_bytes': reg_bytes,
                    'values': values, 'is_atk': is_atk,
                    'start_reg': start_reg,
                    'src_ip': parsed['src_ip'], 'dst_ip': parsed['dst_ip'],
                })
        
        # Writes (FC6, FC16)
        if mb['fc'] in (6, 16) and parsed['src_ip'] == ATTACKER:
            writes.append(mb)
    
    normal_resp = [r for r in responses if not r['is_atk'] and r['dst_ip'] == SCADA]
    atk_resp = [r for r in responses if r['is_atk']]
    
    print(f"Respostas SCADA normais: {len(normal_resp)}")
    print(f"Respostas ao atacante: {len(atk_resp)}")
    print(f"Escritas do atacante: {len(writes)}")
    
    # ================================================================
    # FASE 2: Construir mapa completo de registradores
    # ================================================================
    # (uid, reg_addr) -> [(value, pkt_num, src_ip)]
    reg_map = defaultdict(list)
    
    for resp in normal_resp:
        if resp['start_reg'] < 0:
            continue
        for i, val in enumerate(resp['values']):
            reg_addr = resp['start_reg'] + i
            reg_map[(resp['uid'], reg_addr)].append({
                'value': val,
                'high': (val >> 8) & 0xFF,
                'low': val & 0xFF,
                'pkt': resp['pkt'],
                'src_ip': resp['src_ip'],
            })
    
    # Extrair TODOS os pares (high, low) de valores normais
    all_pairs = []
    for resp in normal_resp:
        for val in resp['values']:
            all_pairs.append(((val >> 8) & 0xFF, val & 0xFF, resp['uid'], resp['pkt'], resp['start_reg']))
    
    print(f"Total de pares (high, low): {len(all_pairs)}")
    
    # ================================================================
    # FASE 3: Mostrar distribuição dos high bytes
    # ================================================================
    high_counts = Counter(p[0] for p in all_pairs)
    max_high = max(high_counts.keys())
    min_high = min(high_counts.keys())
    print(f"\nRange de HIGH bytes: {min_high}-{max_high} ({max_high - min_high + 1} valores)")
    
    # ================================================================
    # FASE 4: BRUTE FORCE - HIGH=posição, LOW=dado
    # ================================================================
    print("\n" + "=" * 70)
    print(" ABORDAGEM 1: HIGH = posição, transform(LOW) = caractere")
    print("=" * 70)
    
    by_high = defaultdict(list)
    for h, l, uid, pkt, sreg in all_pairs:
        by_high[h].append((l, uid, pkt, sreg))
    
    target = list(PREFIX)  # "donotecho{"
    found_approaches = []
    
    # 1a. LOW XOR key
    for key in range(256):
        ok = True
        for pos in range(len(target)):
            if pos not in by_high:
                ok = False; break
            expected = ord(target[pos])
            if not any((lo ^ key) == expected for lo, _, _, _ in by_high[pos]):
                ok = False; break
        if ok:
            flag = decode_with_transform(by_high, lambda lo, pos: lo ^ key, max_high)
            found_approaches.append(('LO XOR 0x{:02X}'.format(key), flag))
            print(f"\n  ✓ LOW XOR 0x{key:02X}: {flag}")
    
    # 1b. LOW + offset
    for offset in range(256):
        ok = True
        for pos in range(len(target)):
            if pos not in by_high:
                ok = False; break
            expected = ord(target[pos])
            if not any(((lo + offset) & 0xFF) == expected for lo, _, _, _ in by_high[pos]):
                ok = False; break
        if ok:
            flag = decode_with_transform(by_high, lambda lo, pos: (lo + offset) & 0xFF, max_high)
            found_approaches.append(('LO + 0x{:02X}'.format(offset), flag))
            print(f"\n  ✓ LOW + 0x{offset:02X}: {flag}")
    
    # 1c. (offset - LOW) mod 256
    for offset in range(256):
        ok = True
        for pos in range(len(target)):
            if pos not in by_high:
                ok = False; break
            expected = ord(target[pos])
            if not any(((offset - lo) & 0xFF) == expected for lo, _, _, _ in by_high[pos]):
                ok = False; break
        if ok:
            flag = decode_with_transform(by_high, lambda lo, pos: (offset - lo) & 0xFF, max_high)
            found_approaches.append(('0x{:02X} - LO'.format(offset), flag))
            print(f"\n  ✓ 0x{offset:02X} - LOW: {flag}")
    
    # 1d. LOW XOR (pos + const)
    for const in range(256):
        ok = True
        for pos in range(len(target)):
            if pos not in by_high:
                ok = False; break
            expected = ord(target[pos])
            key = (pos + const) & 0xFF
            if not any((lo ^ key) == expected for lo, _, _, _ in by_high[pos]):
                ok = False; break
        if ok:
            flag = decode_with_transform(by_high, lambda lo, pos: lo ^ ((pos + const) & 0xFF), max_high)
            found_approaches.append(('LO XOR (pos+0x{:02X})'.format(const), flag))
            print(f"\n  ✓ LOW XOR (pos + 0x{const:02X}): {flag}")
    
    # 1e. LOW XOR (pos * const)
    for const in range(1, 256):
        ok = True
        for pos in range(len(target)):
            if pos not in by_high:
                ok = False; break
            expected = ord(target[pos])
            key = (pos * const) & 0xFF
            if not any((lo ^ key) == expected for lo, _, _, _ in by_high[pos]):
                ok = False; break
        if ok:
            flag = decode_with_transform(by_high, lambda lo, pos: lo ^ ((pos * const) & 0xFF), max_high)
            found_approaches.append(('LO XOR (pos*0x{:02X})'.format(const), flag))
            print(f"\n  ✓ LOW XOR (pos * 0x{const:02X}): {flag}")
    
    # 1f. (LOW + pos + const) mod 256
    for const in range(256):
        ok = True
        for pos in range(len(target)):
            if pos not in by_high:
                ok = False; break
            expected = ord(target[pos])
            if not any(((lo + pos + const) & 0xFF) == expected for lo, _, _, _ in by_high[pos]):
                ok = False; break
        if ok:
            flag = decode_with_transform(by_high, lambda lo, pos: (lo + pos + const) & 0xFF, max_high)
            found_approaches.append(('(LO+pos+0x{:02X})%256'.format(const), flag))
            print(f"\n  ✓ (LOW + pos + 0x{const:02X}) mod 256: {flag}")
    
    # 1g. (HIGH XOR LOW) + offset
    for offset in range(256):
        ok = True
        for pos in range(len(target)):
            if pos not in by_high:
                ok = False; break
            expected = ord(target[pos])
            if not any(((lo ^ pos) + offset) & 0xFF == expected for lo, _, _, _ in by_high[pos]):
                ok = False; break
        if ok:
            flag = decode_with_transform(by_high, lambda lo, pos: ((lo ^ pos) + offset) & 0xFF, max_high)
            found_approaches.append(('(LO^pos)+0x{:02X}'.format(offset), flag))
            print(f"\n  ✓ (LOW ^ pos) + 0x{offset:02X}: {flag}")
    
    # 1h. Value mod N
    by_high_full = defaultdict(list)
    for h, l, uid, pkt, sreg in all_pairs:
        by_high_full[h].append(((h << 8) | l, uid, pkt, sreg))
    
    for N in [128, 100, 96, 85, 83, 80, 64, 58, 48, 42, 256]:
        ok = True
        for pos in range(len(target)):
            if pos not in by_high_full:
                ok = False; break
            expected = ord(target[pos])
            if not any(val % N == expected for val, _, _, _ in by_high_full[pos]):
                ok = False; break
        if ok:
            flag = ""
            for pos in range(max_high + 1):
                if pos in by_high_full:
                    chars = set()
                    for val, _, _, _ in by_high_full[pos]:
                        c = val % N
                        if 32 <= c <= 126:
                            chars.add(chr(c))
                    flag += best_flag_char(chars) if chars else "?"
                else:
                    flag += "?"
            found_approaches.append(('VALUE mod {}'.format(N), flag))
            print(f"\n  ✓ VALUE mod {N}: {flag}")
    
    # ================================================================
    # FASE 5: LOW=posição, HIGH=dado
    # ================================================================
    print("\n" + "=" * 70)
    print(" ABORDAGEM 2: LOW = posição, transform(HIGH) = caractere")
    print("=" * 70)
    
    by_low = defaultdict(list)
    for h, l, uid, pkt, sreg in all_pairs:
        by_low[l].append((h, uid, pkt, sreg))
    
    # Verificar se posições 0-9 existem
    if all(pos in by_low for pos in range(10)):
        for key in range(256):
            ok = True
            for pos in range(len(target)):
                expected = ord(target[pos])
                if not any((hi ^ key) == expected for hi, _, _, _ in by_low[pos]):
                    ok = False; break
            if ok:
                flag = ""
                for pos in range(60):
                    if pos in by_low:
                        chars = set()
                        for hi, _, _, _ in by_low[pos]:
                            c = hi ^ key
                            if 32 <= c <= 126:
                                chars.add(chr(c))
                        flag += best_flag_char(chars) if chars else "?"
                    else:
                        break
                found_approaches.append(('HI XOR 0x{:02X} (pos=LO)'.format(key), flag))
                print(f"\n  ✓ HIGH XOR 0x{key:02X} (pos=LOW): {flag}")
        
        for offset in range(256):
            ok = True
            for pos in range(len(target)):
                expected = ord(target[pos])
                if not any(((hi + offset) & 0xFF) == expected for hi, _, _, _ in by_low[pos]):
                    ok = False; break
            if ok:
                flag = ""
                for pos in range(60):
                    if pos in by_low:
                        chars = set()
                        for hi, _, _, _ in by_low[pos]:
                            c = (hi + offset) & 0xFF
                            if 32 <= c <= 126:
                                chars.add(chr(c))
                        flag += best_flag_char(chars) if chars else "?"
                    else:
                        break
                found_approaches.append(('HI + 0x{:02X} (pos=LO)'.format(offset), flag))
                print(f"\n  ✓ HIGH + 0x{offset:02X} (pos=LOW): {flag}")
    
    # ================================================================
    # FASE 6: Por registro - posição = endereço, dado = valor
    # ================================================================
    print("\n" + "=" * 70)
    print(" ABORDAGEM 3: pos = reg_addr - base, char = f(value)")
    print("=" * 70)
    
    for uid in range(1, 11):
        uid_regs = {addr: vals[0]['value'] for (u, addr), vals in reg_map.items() if u == uid}
        if not uid_regs:
            continue
        
        for base in [0, 100, 200, 1000, 2000, 4000]:
            mapped = {}
            for addr, val in uid_regs.items():
                pos = addr - base
                if 0 <= pos < 60:
                    mapped[pos] = val
            
            if not mapped or not all(p in mapped for p in range(min(10, len(target)))):
                continue
            
            # Tentar: high byte + offset
            for offset in range(256):
                ok = True
                for pos in range(min(len(target), max(mapped.keys())+1)):
                    if pos not in mapped:
                        ok = False; break
                    c = ((mapped[pos] >> 8) + offset) & 0xFF
                    if pos < len(target) and chr(c) != target[pos]:
                        ok = False; break
                if ok:
                    flag = ""
                    for pos in range(max(mapped.keys()) + 1):
                        if pos in mapped:
                            c = ((mapped[pos] >> 8) + offset) & 0xFF
                            flag += chr(c) if 32 <= c <= 126 else "."
                        else:
                            flag += "?"
                    print(f"\n  ✓ Unit {uid}, base={base}, HI+0x{offset:02X}: {flag}")
                    found_approaches.append((f'U{uid} base{base} HI+0x{offset:02X}', flag))
            
            # Tentar: low byte + offset
            for offset in range(256):
                ok = True
                for pos in range(min(len(target), max(mapped.keys())+1)):
                    if pos not in mapped:
                        ok = False; break
                    c = ((mapped[pos] & 0xFF) + offset) & 0xFF
                    if pos < len(target) and chr(c) != target[pos]:
                        ok = False; break
                if ok:
                    flag = ""
                    for pos in range(max(mapped.keys()) + 1):
                        if pos in mapped:
                            c = ((mapped[pos] & 0xFF) + offset) & 0xFF
                            flag += chr(c) if 32 <= c <= 126 else "."
                        else:
                            flag += "?"
                    print(f"\n  ✓ Unit {uid}, base={base}, LO+0x{offset:02X}: {flag}")
                    found_approaches.append((f'U{uid} base{base} LO+0x{offset:02X}', flag))
            
            # Tentar: high XOR key
            for key in range(256):
                ok = True
                for pos in range(min(len(target), max(mapped.keys())+1)):
                    if pos not in mapped:
                        ok = False; break
                    c = ((mapped[pos] >> 8) ^ key) & 0xFF
                    if pos < len(target) and chr(c) != target[pos]:
                        ok = False; break
                if ok:
                    flag = ""
                    for pos in range(max(mapped.keys()) + 1):
                        if pos in mapped:
                            c = ((mapped[pos] >> 8) ^ key) & 0xFF
                            flag += chr(c) if 32 <= c <= 126 else "."
                        else:
                            flag += "?"
                    print(f"\n  ✓ Unit {uid}, base={base}, HI^0x{key:02X}: {flag}")
                    found_approaches.append((f'U{uid} base{base} HI^0x{key:02X}', flag))
            
            # Tentar: low XOR key
            for key in range(256):
                ok = True
                for pos in range(min(len(target), max(mapped.keys())+1)):
                    if pos not in mapped:
                        ok = False; break
                    c = ((mapped[pos] & 0xFF) ^ key) & 0xFF
                    if pos < len(target) and chr(c) != target[pos]:
                        ok = False; break
                if ok:
                    flag = ""
                    for pos in range(max(mapped.keys()) + 1):
                        if pos in mapped:
                            c = ((mapped[pos] & 0xFF) ^ key) & 0xFF
                            flag += chr(c) if 32 <= c <= 126 else "."
                        else:
                            flag += "?"
                    print(f"\n  ✓ Unit {uid}, base={base}, LO^0x{key:02X}: {flag}")
                    found_approaches.append((f'U{uid} base{base} LO^0x{key:02X}', flag))
    
    # ================================================================
    # FASE 7: Um caractere por resposta
    # ================================================================
    print("\n" + "=" * 70)
    print(" ABORDAGEM 4: Um caractere por resposta (em ordem)")
    print("=" * 70)
    
    extractors = {
        'first_hi': lambda r: r['values'][0] >> 8 if r['values'] else 0,
        'first_lo': lambda r: r['values'][0] & 0xFF if r['values'] else 0,
        'last_hi': lambda r: r['values'][-1] >> 8 if r['values'] else 0,
        'last_lo': lambda r: r['values'][-1] & 0xFF if r['values'] else 0,
        'xor_bytes': lambda r: xor_all(r['reg_bytes']),
        'sum_mod128': lambda r: sum(r['values']) % 128 if r['values'] else 0,
        'sum_mod256': lambda r: sum(r['values']) % 256 if r['values'] else 0,
        'bytecnt': lambda r: r['byte_count'],
        'mid_hi': lambda r: r['values'][len(r['values'])//2] >> 8 if r['values'] else 0,
        'mid_lo': lambda r: r['values'][len(r['values'])//2] & 0xFF if r['values'] else 0,
    }
    
    for name, extractor in extractors.items():
        vals = [extractor(r) for r in normal_resp]
        for key in range(256):
            text = ''.join(chr((v ^ key) & 0xFF) if 32 <= ((v ^ key) & 0xFF) <= 126 else '.' for v in vals)
            if 'donotecho' in text:
                print(f"\n  ✓ {name} XOR 0x{key:02X}: {text}")
                found_approaches.append((f'{name}_XOR_0x{key:02X}', text))
        
        for off in range(256):
            text = ''.join(chr((v + off) & 0xFF) if 32 <= ((v + off) & 0xFF) <= 126 else '.' for v in vals)
            if 'donotecho' in text:
                print(f"\n  ✓ {name} ADD 0x{off:02X}: {text}")
                found_approaches.append((f'{name}_ADD_0x{off:02X}', text))
    
    # ================================================================
    # FASE 8: Busca direta no PCAP raw
    # ================================================================
    print("\n" + "=" * 70)
    print(" ABORDAGEM 5: Busca XOR no PCAP raw")
    print("=" * 70)
    
    flag_bytes = b"donotecho{"
    for key in range(256):
        xored = bytes([b ^ key for b in flag_bytes])
        pos = raw_data.find(xored)
        if pos >= 0:
            end = min(pos + 80, len(raw_data))
            decoded = bytes([b ^ key for b in raw_data[pos:end]])
            text = decoded.decode('ascii', errors='replace')
            brace = text.find('}')
            if brace > 0:
                text = text[:brace+1]
            print(f"\n  ✓ XOR 0x{key:02X} @ offset {pos}: {text}")
            found_approaches.append((f'RAW_XOR_0x{key:02X}', text))
    
    # ================================================================
    # FASE 9: Concatenação por unit + multi-byte XOR
    # ================================================================
    print("\n" + "=" * 70)
    print(" ABORDAGEM 6: Concatenação por unit + XOR com chave do atacante")
    print("=" * 70)
    
    atk_key = bytes([0x73, 0x2C, 0x26, 0x1D, 0x21, 0x72, 0x2C])
    
    for uid in range(1, 11):
        unit_bytes = bytearray()
        for resp in normal_resp:
            if resp['uid'] == uid:
                unit_bytes.extend(resp['reg_bytes'])
        if not unit_bytes:
            continue
        
        # XOR com chave do atacante
        decoded = bytes([unit_bytes[i] ^ atk_key[i % len(atk_key)] for i in range(len(unit_bytes))])
        text = decoded.decode('ascii', errors='replace')
        if 'donotecho' in text or 'flag' in text.lower():
            print(f"\n  ✓ Unit {uid} XOR atk_key: {text[:100]}")
        
        # Só high bytes XOR chave
        high_bytes = bytearray(unit_bytes[i] for i in range(0, len(unit_bytes), 2))
        for key in range(256):
            decoded = bytes([(b ^ key) & 0xFF for b in high_bytes])
            text = decoded.decode('ascii', errors='replace')
            if 'donotecho' in text:
                print(f"\n  ✓ Unit {uid} HI_ONLY XOR 0x{key:02X}: {text[:80]}")
        
        # Só low bytes XOR chave
        low_bytes = bytearray(unit_bytes[i] for i in range(1, len(unit_bytes), 2))
        for key in range(256):
            decoded = bytes([(b ^ key) & 0xFF for b in low_bytes])
            text = decoded.decode('ascii', errors='replace')
            if 'donotecho' in text:
                print(f"\n  ✓ Unit {uid} LO_ONLY XOR 0x{key:02X}: {text[:80]}")
    
    # ================================================================
    # FASE 10: Estatísticas e melhor candidato por MODE
    # ================================================================
    print("\n" + "=" * 70)
    print(" ESTATÍSTICAS: Byte mais comum por posição (HIGH=pos)")
    print("=" * 70)
    
    for pos in range(max_high + 1):
        if pos in by_high:
            lo_counter = Counter(lo for lo, _, _, _ in by_high[pos])
            mode_lo, mode_count = lo_counter.most_common(1)[0]
            total = len(by_high[pos])
            
            # Mostrar com diferentes offsets
            candidates = []
            for off in [0x50, 0x56, 0x40, 0x60, 0x00]:
                c = (mode_lo + off) & 0xFF
                if 32 <= c <= 126:
                    candidates.append(f"+0x{off:02X}='{chr(c)}'")
            for k in [0x42, 0x6A, 0x55]:
                c = mode_lo ^ k
                if 32 <= c <= 126:
                    candidates.append(f"^0x{k:02X}='{chr(c)}'")
            
            raw_c = chr(mode_lo) if 32 <= mode_lo <= 126 else '.'
            print(f"  pos {pos:2d}: mode=0x{mode_lo:02X} raw='{raw_c}' ({mode_count}/{total}) {' | '.join(candidates[:4])}")
    
    # ================================================================
    # RESULTADO FINAL
    # ================================================================
    print("\n" + "=" * 70)
    print(" RESULTADOS")
    print("=" * 70)
    
    if found_approaches:
        # Rankear por score
        scored = [(name, flag, flag_score(flag)) for name, flag in found_approaches]
        scored.sort(key=lambda x: -x[2])
        
        print(f"\n  {len(scored)} abordagens encontraram match!")
        for name, flag, score in scored[:20]:
            print(f"\n  [{score:3d}] {name}")
            print(f"        {flag}")
    else:
        print("\n  NENHUMA abordagem encontrou 'donotecho{' diretamente.")
        print("  Verifique a seção de estatísticas acima para pistas.")
        
        # Mostrar flag pelo MODE dos low bytes (melhor palpite)
        print("\n  MELHOR PALPITE (mode dos low bytes por posição):")
        for off_name, offset in [("raw", 0), ("+0x50", 0x50), ("+0x56", 0x56), ("+0x40", 0x40)]:
            flag = ""
            for pos in range(max_high + 1):
                if pos in by_high:
                    lo_counter = Counter(lo for lo, _, _, _ in by_high[pos])
                    mode_lo = lo_counter.most_common(1)[0][0]
                    c = (mode_lo + offset) & 0xFF
                    flag += chr(c) if 32 <= c <= 126 else "."
                else:
                    flag += "?"
            print(f"    {off_name}: {flag}")
    
    print("\n" + "=" * 70)
    print(" FIM DA ANÁLISE")
    print("=" * 70)


def decode_with_transform(by_high, transform_fn, max_pos):
    """Decodifica flag usando transform nos low bytes, resolvendo ambiguidades."""
    flag = ""
    for pos in range(max_pos + 1):
        if pos in by_high:
            chars = Counter()
            for lo, uid, pkt, sreg in by_high[pos]:
                c = transform_fn(lo, pos)
                if 32 <= c <= 126:
                    chars[chr(c)] += 1
            if chars:
                flag += best_flag_char(set(chars.keys()), chars)
            else:
                flag += "."
        else:
            flag += "?"
    return flag


def best_flag_char(char_set, counter=None):
    """Escolhe o melhor caractere para a flag, priorizando chars do flag charset."""
    if not char_set:
        return "?"
    if len(char_set) == 1:
        return list(char_set)[0]
    
    # Priorizar por frequência se counter disponível
    if counter:
        # Filtrar por chars válidos na flag
        valid = {c: counter[c] for c in char_set if c in FLAG_CHARS}
        if valid:
            return max(valid, key=valid.get)
        return max(counter, key=counter.get)
    
    # Priorizar chars do flag charset
    valid = [c for c in char_set if c in FLAG_CHARS]
    if valid:
        return valid[0]
    return list(char_set)[0]


def xor_all(data):
    result = 0
    for b in data:
        result ^= b
    return result


if __name__ == "__main__":
    main()
