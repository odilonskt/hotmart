#!/usr/bin/env python3
"""
INDUSTRIAL MELTDOWN - FINAL FLAG DECODER
Brute-force all possible encodings on the Modbus register data.
"""

import struct
import os
import base64
import itertools

TARGET = "donotecho{"  # Known flag prefix

def read_pcap(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    snaplen = struct.unpack(f'{endian}I', data[16:20])[0]
    offset = 24
    packets = []
    while offset < len(data) - 16:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', data[offset:offset+16])
        if incl_len > snaplen or incl_len > len(data) - offset - 16:
            break
        packets.append(data[offset+16:offset+16+incl_len])
        offset += 16 + incl_len
    return packets


def parse_modbus_responses(packets):
    """Extract all Modbus FC3 responses from normal SCADA traffic."""
    results = []
    attacker = "192.168.100.200"
    scada = "192.168.100.20"
    
    for pkt_idx, pkt in enumerate(packets):
        if len(pkt) < 54:
            continue
        ethertype = struct.unpack('>H', pkt[12:14])[0]
        if ethertype != 0x0800:
            continue
        ip = pkt[14:]
        if len(ip) < 20:
            continue
        protocol = ip[9]
        if protocol != 6:
            continue
        ihl = (ip[0] & 0xF) * 4
        src_ip = '.'.join(str(b) for b in ip[12:16])
        dst_ip = '.'.join(str(b) for b in ip[16:20])
        
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        src_port = struct.unpack('>H', tcp[0:2])[0]
        dst_port = struct.unpack('>H', tcp[2:4])[0]
        data_off = ((tcp[12] >> 4) & 0xF) * 4
        payload = tcp[data_off:]
        
        if len(payload) < 9:
            continue
        
        trans_id = struct.unpack('>H', payload[0:2])[0]
        unit_id = payload[6]
        fc = payload[7]
        mb_data = payload[8:]
        
        # FC3 response (from PLC, source port 502)
        if fc == 3 and src_port == 502 and len(mb_data) >= 3:
            byte_count = mb_data[0]
            if len(mb_data) >= 1 + byte_count and byte_count >= 2:
                reg_bytes = mb_data[1:1+byte_count]
                values = []
                for i in range(0, byte_count, 2):
                    if i + 1 < byte_count:
                        values.append(struct.unpack('>H', reg_bytes[i:i+2])[0])
                
                is_attacker = (dst_ip == attacker)
                is_scada = (dst_ip == scada)
                
                results.append({
                    'pkt': pkt_idx,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'trans_id': trans_id,
                    'unit_id': unit_id,
                    'byte_count': byte_count,
                    'reg_bytes': reg_bytes,
                    'values': values,
                    'is_attacker': is_attacker,
                    'is_scada': is_scada,
                })
    
    return results


def extract_requests(packets):
    """Extract all Modbus FC3 requests to get register addresses."""
    results = {}
    for pkt_idx, pkt in enumerate(packets):
        if len(pkt) < 54:
            continue
        ethertype = struct.unpack('>H', pkt[12:14])[0]
        if ethertype != 0x0800:
            continue
        ip = pkt[14:]
        if len(ip) < 20 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0xF) * 4
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        dst_port = struct.unpack('>H', tcp[2:4])[0]
        data_off = ((tcp[12] >> 4) & 0xF) * 4
        payload = tcp[data_off:]
        if len(payload) < 12 or dst_port != 502:
            continue
        trans_id = struct.unpack('>H', payload[0:2])[0]
        fc = payload[7]
        mb_data = payload[8:]
        if fc == 3 and len(mb_data) >= 4:
            start_reg = struct.unpack('>H', mb_data[0:2])[0]
            num_regs = struct.unpack('>H', mb_data[2:4])[0]
            results[trans_id] = {'start_reg': start_reg, 'num_regs': num_regs, 'pkt': pkt_idx}
    return results


def check_flag(text, min_len=10):
    """Check if text contains a flag pattern."""
    if "donotecho{" in text:
        return True
    if "donotecho" in text:
        return True
    if "flag{" in text.lower():
        return True
    return False


def printable_ratio(text):
    """Return ratio of printable ASCII chars."""
    if not text:
        return 0
    return sum(1 for c in text if 32 <= ord(c) <= 126) / len(text)


def main():
    filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "industrial_meltdown.pcap")
    packets = read_pcap(filepath)
    responses = parse_modbus_responses(packets)
    requests = extract_requests(packets)
    
    # Separate normal SCADA responses from attacker responses
    scada_responses = [r for r in responses if r['is_scada']]
    attacker_responses = [r for r in responses if r['is_attacker']]
    
    print(f"Total responses: {len(responses)}")
    print(f"SCADA responses: {len(scada_responses)}")
    print(f"Attacker responses: {len(attacker_responses)}")
    
    # Build register map: correlate requests with responses by TransID
    reg_values = []  # List of (unit, reg_addr, value, pkt_idx)
    for resp in responses:
        tid = resp['trans_id']
        if tid in requests:
            req = requests[tid]
            start_reg = req['start_reg']
            for i, val in enumerate(resp['values']):
                reg_values.append({
                    'unit': resp['unit_id'],
                    'reg': start_reg + i,
                    'value': val,
                    'high': (val >> 8) & 0xFF,
                    'low': val & 0xFF,
                    'pkt': resp['pkt'],
                    'is_attacker': resp['is_attacker'],
                })
    
    print(f"Total register values mapped: {len(reg_values)}")
    
    # Filter to only normal SCADA data
    normal_regs = [r for r in reg_values if not r['is_attacker']]
    print(f"Normal SCADA register values: {len(normal_regs)}")
    
    print("\n" + "=" * 80)
    print(" APPROACH 1: HIGH BYTE = POSITION, LOW BYTE = DATA (with XOR key)")
    print("=" * 80)
    
    # Group by high byte value
    by_high = {}
    for r in normal_regs:
        h = r['high']
        if h not in by_high:
            by_high[h] = []
        by_high[h].append(r)
    
    print(f"\nHigh byte range: {min(by_high.keys())} to {max(by_high.keys())}")
    print(f"Number of unique high values: {len(by_high)}")
    
    # For positions 0-9, we expect "donotecho{"
    target_chars = list(TARGET)
    
    # Try XOR: for each key, check if consistent across all data at position 0-9
    print("\nTrying XOR key on low bytes (position = high byte)...")
    for key in range(256):
        match = True
        for pos in range(len(target_chars)):
            expected = ord(target_chars[pos])
            if pos not in by_high:
                match = False
                break
            # Check if ANY low byte at this position XOR key = expected
            found = False
            for r in by_high[pos]:
                if (r['low'] ^ key) == expected:
                    found = True
                    break
            if not found:
                match = False
                break
        if match:
            # Decode full flag
            flag = {}
            for pos in sorted(by_high.keys()):
                chars_at_pos = set()
                for r in by_high[pos]:
                    c = r['low'] ^ key
                    if 32 <= c <= 126:
                        chars_at_pos.add(chr(c))
                if chars_at_pos:
                    flag[pos] = chars_at_pos
            
            flag_str = ""
            for pos in range(max(by_high.keys()) + 1):
                if pos in flag:
                    chars = flag[pos]
                    if len(chars) == 1:
                        flag_str += list(chars)[0]
                    else:
                        flag_str += f"[{''.join(sorted(chars))}]"
                else:
                    flag_str += "?"
            
            print(f"\n  *** XOR KEY 0x{key:02X} ({key}) MATCHES! ***")
            print(f"  Flag: {flag_str}")
    
    # Try ADD offset: low + offset = char
    print("\nTrying ADD offset on low bytes (position = high byte)...")
    for offset in range(256):
        match = True
        for pos in range(len(target_chars)):
            expected = ord(target_chars[pos])
            if pos not in by_high:
                match = False
                break
            found = False
            for r in by_high[pos]:
                if ((r['low'] + offset) & 0xFF) == expected:
                    found = True
                    break
            if not found:
                match = False
                break
        if match:
            flag = {}
            for pos in sorted(by_high.keys()):
                chars_at_pos = set()
                for r in by_high[pos]:
                    c = (r['low'] + offset) & 0xFF
                    if 32 <= c <= 126:
                        chars_at_pos.add(chr(c))
                if chars_at_pos:
                    flag[pos] = chars_at_pos
            
            flag_str = ""
            for pos in range(max(by_high.keys()) + 1):
                if pos in flag:
                    chars = flag[pos]
                    if len(chars) == 1:
                        flag_str += list(chars)[0]
                    else:
                        flag_str += f"[{''.join(sorted(chars))}]"
                else:
                    flag_str += "?"
            
            print(f"\n  *** ADD OFFSET 0x{offset:02X} ({offset}) MATCHES! ***")
            print(f"  Flag: {flag_str}")
    
    # Try SUB: char = offset - low
    print("\nTrying SUB offset on low bytes (position = high byte)...")
    for offset in range(256):
        match = True
        for pos in range(len(target_chars)):
            expected = ord(target_chars[pos])
            if pos not in by_high:
                match = False
                break
            found = False
            for r in by_high[pos]:
                if ((offset - r['low']) & 0xFF) == expected:
                    found = True
                    break
            if not found:
                match = False
                break
        if match:
            flag = {}
            for pos in sorted(by_high.keys()):
                chars_at_pos = set()
                for r in by_high[pos]:
                    c = (offset - r['low']) & 0xFF
                    if 32 <= c <= 126:
                        chars_at_pos.add(chr(c))
                if chars_at_pos:
                    flag[pos] = chars_at_pos
            
            flag_str = ""
            for pos in range(max(by_high.keys()) + 1):
                if pos in flag:
                    chars = flag[pos]
                    if len(chars) == 1:
                        flag_str += list(chars)[0]
                    else:
                        flag_str += f"[{''.join(sorted(chars))}]"
                else:
                    flag_str += "?"
            
            print(f"\n  *** SUB OFFSET 0x{offset:02X} ({offset}) MATCHES! ***")
            print(f"  Flag: {flag_str}")
    
    # Also try: char = (high XOR low) + offset
    print("\nTrying (HIGH XOR LOW) + offset...")
    for offset in range(256):
        match = True
        for pos in range(len(target_chars)):
            expected = ord(target_chars[pos])
            if pos not in by_high:
                match = False
                break
            found = False
            for r in by_high[pos]:
                xval = r['high'] ^ r['low']
                if ((xval + offset) & 0xFF) == expected:
                    found = True
                    break
            if not found:
                match = False
                break
        if match:
            flag = {}
            for pos in sorted(by_high.keys()):
                chars_at_pos = set()
                for r in by_high[pos]:
                    c = ((r['high'] ^ r['low']) + offset) & 0xFF
                    if 32 <= c <= 126:
                        chars_at_pos.add(chr(c))
                if chars_at_pos:
                    flag[pos] = chars_at_pos
            
            flag_str = ""
            for pos in range(max(by_high.keys()) + 1):
                if pos in flag:
                    chars = flag[pos]
                    if len(chars) == 1:
                        flag_str += list(chars)[0]
                    else:
                        flag_str += f"[{''.join(sorted(chars))}]"
                else:
                    flag_str += "?"
            
            print(f"\n  *** (HI^LO)+OFFSET 0x{offset:02X} ({offset}) MATCHES! ***")
            print(f"  Flag: {flag_str}")
    
    # Try: char = (high + low) mod 256 + offset  
    print("\nTrying (HIGH + LOW) mod 256 + offset...")
    for offset in range(256):
        match = True
        for pos in range(len(target_chars)):
            expected = ord(target_chars[pos])
            if pos not in by_high:
                match = False
                break
            found = False
            for r in by_high[pos]:
                sval = (r['high'] + r['low']) & 0xFF
                if ((sval + offset) & 0xFF) == expected:
                    found = True
                    break
            if not found:
                match = False
                break
        if match:
            flag = {}
            for pos in sorted(by_high.keys()):
                chars_at_pos = set()
                for r in by_high[pos]:
                    c = ((r['high'] + r['low'] + offset)) & 0xFF
                    if 32 <= c <= 126:
                        chars_at_pos.add(chr(c))
                if chars_at_pos:
                    flag[pos] = chars_at_pos
            
            flag_str = ""
            for pos in range(max(by_high.keys()) + 1):
                if pos in flag:
                    chars = flag[pos]
                    if len(chars) == 1:
                        flag_str += list(chars)[0]
                    else:
                        flag_str += f"[{''.join(sorted(chars))}]"
                else:
                    flag_str += "?"
            
            print(f"\n  *** (HI+LO)+OFFSET 0x{offset:02X} ({offset}) MATCHES! ***")
            print(f"  Flag: {flag_str}")
    
    print("\n" + "=" * 80)
    print(" APPROACH 2: LOW BYTE = POSITION, HIGH BYTE = DATA (with XOR/ADD)")
    print("=" * 80)
    
    by_low = {}
    for r in normal_regs:
        lo = r['low']
        if lo not in by_low:
            by_low[lo] = []
        by_low[lo].append(r)
    
    # Check if positions 0-9 exist in low bytes
    valid = all(pos in by_low for pos in range(10))
    if valid:
        print(f"\nPositions 0-9 found in low bytes. Testing...")
        for key in range(256):
            match = True
            for pos in range(len(target_chars)):
                expected = ord(target_chars[pos])
                found = False
                for r in by_low[pos]:
                    if (r['high'] ^ key) == expected:
                        found = True
                        break
                if not found:
                    match = False
                    break
            if match:
                flag = {}
                for pos in sorted(by_low.keys()):
                    if pos > 127:
                        continue
                    chars_at_pos = set()
                    for r in by_low[pos]:
                        c = r['high'] ^ key
                        if 32 <= c <= 126:
                            chars_at_pos.add(chr(c))
                    if chars_at_pos:
                        flag[pos] = chars_at_pos
                
                max_pos = max(flag.keys()) if flag else 0
                flag_str = ""
                for pos in range(min(max_pos + 1, 80)):
                    if pos in flag:
                        chars = flag[pos]
                        if len(chars) == 1:
                            flag_str += list(chars)[0]
                        else:
                            flag_str += f"[{''.join(sorted(chars))}]"
                    else:
                        flag_str += "?"
                
                print(f"\n  *** LOW=POS, XOR KEY 0x{key:02X} MATCHES! ***")
                print(f"  Flag: {flag_str}")
        
        # Also try ADD offset on high byte
        for offset in range(256):
            match = True
            for pos in range(len(target_chars)):
                expected = ord(target_chars[pos])
                found = False
                for r in by_low[pos]:
                    if ((r['high'] + offset) & 0xFF) == expected:
                        found = True
                        break
                if not found:
                    match = False
                    break
            if match:
                flag = {}
                for pos in sorted(by_low.keys()):
                    if pos > 127:
                        continue
                    chars_at_pos = set()
                    for r in by_low[pos]:
                        c = (r['high'] + offset) & 0xFF
                        if 32 <= c <= 126:
                            chars_at_pos.add(chr(c))
                    if chars_at_pos:
                        flag[pos] = chars_at_pos
                
                max_pos = max(flag.keys()) if flag else 0
                flag_str = ""
                for pos in range(min(max_pos + 1, 80)):
                    if pos in flag:
                        chars = flag[pos]
                        if len(chars) == 1:
                            flag_str += list(chars)[0]
                        else:
                            flag_str += f"[{''.join(sorted(chars))}]"
                    else:
                        flag_str += "?"
                
                print(f"\n  *** LOW=POS, ADD 0x{offset:02X} MATCHES! ***")
                print(f"  Flag: {flag_str}")
    else:
        print("  Not all positions 0-9 found in low bytes")
    
    print("\n" + "=" * 80)
    print(" APPROACH 3: ONE CHAR PER RESPONSE PACKET")
    print("=" * 80)
    
    # Extract one value per response using different methods
    methods = {
        'first_high': lambda r: r['values'][0] >> 8 if r['values'] else 0,
        'first_low': lambda r: r['values'][0] & 0xFF if r['values'] else 0,
        'last_high': lambda r: r['values'][-1] >> 8 if r['values'] else 0,
        'last_low': lambda r: r['values'][-1] & 0xFF if r['values'] else 0,
        'xor_all': lambda r: eval('0' + ''.join(f'^{b}' for b in r['reg_bytes'])),
        'sum_mod128': lambda r: sum(r['values']) % 128,
        'sum_mod256': lambda r: sum(r['values']) % 256,
        'byte_count': lambda r: r['byte_count'],
        'unit_id': lambda r: r['unit_id'],
        'first_val_mod128': lambda r: r['values'][0] % 128 if r['values'] else 0,
        'first_val_div50': lambda r: r['values'][0] // 50 if r['values'] else 0,
    }
    
    for method_name, method_fn in methods.items():
        values = []
        for resp in scada_responses:
            try:
                values.append(method_fn(resp))
            except:
                values.append(0)
        
        # Try with offsets
        for offset in range(256):
            text = ""
            for v in values:
                c = (v + offset) & 0xFF
                text += chr(c) if 32 <= c <= 126 else '.'
            
            if check_flag(text):
                print(f"\n  *** METHOD '{method_name}' + OFFSET 0x{offset:02X} ***")
                print(f"  Text: {text}")
        
        # Try with XOR
        for key in range(256):
            text = ""
            for v in values:
                c = (v ^ key) & 0xFF
                text += chr(c) if 32 <= c <= 126 else '.'
            
            if check_flag(text):
                print(f"\n  *** METHOD '{method_name}' XOR 0x{key:02X} ***")
                print(f"  Text: {text}")
    
    print("\n" + "=" * 80)
    print(" APPROACH 4: REGISTER VALUE / N = ASCII")
    print("=" * 80)
    
    # For each response, try dividing first register value by N
    for N in range(1, 500):
        text = ""
        valid_count = 0
        for resp in scada_responses:
            if resp['values']:
                c = resp['values'][0] // N
                if 32 <= c <= 126:
                    text += chr(c)
                    valid_count += 1
                else:
                    text += '.'
            else:
                text += '.'
        
        if check_flag(text):
            print(f"\n  *** VALUE / {N} ***")
            print(f"  Text: {text}")
    
    print("\n" + "=" * 80)
    print(" APPROACH 5: POSITION FROM REGISTER ADDRESS")
    print("=" * 80)
    
    # Use register address as position, value as data
    for unit in range(1, 11):
        unit_data = [(r['reg'], r['value']) for r in normal_regs if r['unit'] == unit]
        if not unit_data:
            continue
        
        # Sort by register address
        unit_data.sort()
        
        # Try different register-to-position mappings
        for reg_offset in [0, 100, 200, 1000, 2000, 4000]:
            chars_by_pos = {}
            for reg, val in unit_data:
                pos = reg - reg_offset
                if 0 <= pos < 100:
                    chars_by_pos[pos] = val
            
            if not chars_by_pos:
                continue
            
            # Try: high byte of value with offset
            for offset in range(256):
                text = ""
                match_count = 0
                for pos in range(min(len(target_chars), max(chars_by_pos.keys()) + 1)):
                    if pos in chars_by_pos:
                        c = ((chars_by_pos[pos] >> 8) + offset) & 0xFF
                        if 32 <= c <= 126:
                            text += chr(c)
                            if pos < len(target_chars) and chr(c) == target_chars[pos]:
                                match_count += 1
                        else:
                            text += '.'
                    else:
                        text += '?'
                
                if match_count >= 5:
                    full_text = ""
                    for pos in range(max(chars_by_pos.keys()) + 1):
                        if pos in chars_by_pos:
                            c = ((chars_by_pos[pos] >> 8) + offset) & 0xFF
                            full_text += chr(c) if 32 <= c <= 126 else '.'
                        else:
                            full_text += '?'
                    print(f"\n  Unit {unit}, RegOffset {reg_offset}, HI+0x{offset:02X}: match={match_count}")
                    print(f"  Text: {full_text}")
            
            # Try: low byte of value with offset
            for offset in range(256):
                text = ""
                match_count = 0
                for pos in range(min(len(target_chars), max(chars_by_pos.keys()) + 1)):
                    if pos in chars_by_pos:
                        c = ((chars_by_pos[pos] & 0xFF) + offset) & 0xFF
                        if pos < len(target_chars) and 32 <= c <= 126 and chr(c) == target_chars[pos]:
                            match_count += 1
                
                if match_count >= 5:
                    full_text = ""
                    for pos in range(max(chars_by_pos.keys()) + 1):
                        if pos in chars_by_pos:
                            c = ((chars_by_pos[pos] & 0xFF) + offset) & 0xFF
                            full_text += chr(c) if 32 <= c <= 126 else '.'
                        else:
                            full_text += '?'
                    print(f"\n  Unit {unit}, RegOffset {reg_offset}, LO+0x{offset:02X}: match={match_count}")
                    print(f"  Text: {full_text}")
            
            # Try: value XOR key
            for key in range(256):
                match_count = 0
                for pos in range(min(len(target_chars), max(chars_by_pos.keys()) + 1)):
                    if pos in chars_by_pos:
                        c = ((chars_by_pos[pos] >> 8) ^ key) & 0xFF
                        if pos < len(target_chars) and 32 <= c <= 126 and chr(c) == target_chars[pos]:
                            match_count += 1
                
                if match_count >= 5:
                    full_text = ""
                    for pos in range(max(chars_by_pos.keys()) + 1):
                        if pos in chars_by_pos:
                            c = ((chars_by_pos[pos] >> 8) ^ key) & 0xFF
                            full_text += chr(c) if 32 <= c <= 126 else '.'
                        else:
                            full_text += '?'
                    print(f"\n  Unit {unit}, RegOffset {reg_offset}, HI^0x{key:02X}: match={match_count}")
                    print(f"  Text: {full_text}")
    
    print("\n" + "=" * 80)
    print(" APPROACH 6: MULTI-BYTE XOR ON CONCATENATED DATA")
    print("=" * 80)
    
    # Concatenate all register bytes from normal SCADA per unit
    for unit in range(1, 11):
        unit_bytes = bytearray()
        for resp in scada_responses:
            if resp['unit_id'] == unit:
                unit_bytes.extend(resp['reg_bytes'])
        
        if len(unit_bytes) < 10:
            continue
        
        # Try multi-byte XOR with attacker's write values
        atk_key = bytes([0x73, 0x2C, 0x26, 0x1D, 0x21, 0x72, 0x2C])
        decoded = bytes([unit_bytes[i] ^ atk_key[i % len(atk_key)] for i in range(len(unit_bytes))])
        ratio = printable_ratio(decoded.decode('ascii', errors='replace'))
        if ratio > 0.5 or check_flag(decoded.decode('ascii', errors='replace')):
            print(f"\n  Unit {unit}, XOR with attacker key: ratio={ratio:.0%}")
            print(f"  Text: {decoded.decode('ascii', errors='replace')[:100]}")
        
        # Try XOR with key derived from unit ID
        for key_base in range(256):
            key = bytes([(key_base + i) & 0xFF for i in range(8)])
            decoded = bytes([unit_bytes[i] ^ key[i % len(key)] for i in range(len(unit_bytes))])
            text = decoded.decode('ascii', errors='replace')
            if check_flag(text):
                print(f"\n  Unit {unit}, XOR sequential key base 0x{key_base:02X}")
                print(f"  Text: {text[:100]}")
    
    print("\n" + "=" * 80)
    print(" APPROACH 7: POSITION-DEPENDENT XOR")
    print("=" * 80)
    
    # char = low_byte XOR f(position)
    # Try: f(pos) = pos + constant
    for const in range(256):
        match = True
        for pos in range(len(target_chars)):
            expected = ord(target_chars[pos])
            if pos not in by_high:
                match = False
                break
            key = (pos + const) & 0xFF
            found = any((r['low'] ^ key) == expected for r in by_high[pos])
            if not found:
                match = False
                break
        if match:
            flag_str = ""
            for pos in range(max(by_high.keys()) + 1):
                if pos in by_high:
                    key = (pos + const) & 0xFF
                    chars = set()
                    for r in by_high[pos]:
                        c = r['low'] ^ key
                        if 32 <= c <= 126:
                            chars.add(chr(c))
                    if len(chars) == 1:
                        flag_str += list(chars)[0]
                    elif chars:
                        flag_str += f"[{''.join(sorted(chars))}]"
                    else:
                        flag_str += "."
                else:
                    flag_str += "?"
            print(f"\n  *** POS-XOR (pos+0x{const:02X}) MATCHES! ***")
            print(f"  Flag: {flag_str}")
    
    # Try: f(pos) = pos * constant
    for const in range(1, 256):
        match = True
        for pos in range(len(target_chars)):
            expected = ord(target_chars[pos])
            if pos not in by_high:
                match = False
                break
            key = (pos * const) & 0xFF
            found = any((r['low'] ^ key) == expected for r in by_high[pos])
            if not found:
                match = False
                break
        if match:
            flag_str = ""
            for pos in range(max(by_high.keys()) + 1):
                if pos in by_high:
                    key = (pos * const) & 0xFF
                    chars = set()
                    for r in by_high[pos]:
                        c = r['low'] ^ key
                        if 32 <= c <= 126:
                            chars.add(chr(c))
                    if len(chars) == 1:
                        flag_str += list(chars)[0]
                    elif chars:
                        flag_str += f"[{''.join(sorted(chars))}]"
                    else:
                        flag_str += "."
                else:
                    flag_str += "?"
            print(f"\n  *** POS-XOR (pos*0x{const:02X}) MATCHES! ***")
            print(f"  Flag: {flag_str}")
    
    # Try: char = (low + pos) mod 256 + offset
    for offset in range(256):
        match = True
        for pos in range(len(target_chars)):
            expected = ord(target_chars[pos])
            if pos not in by_high:
                match = False
                break
            found = any(((r['low'] + pos + offset) & 0xFF) == expected for r in by_high[pos])
            if not found:
                match = False
                break
        if match:
            flag_str = ""
            for pos in range(max(by_high.keys()) + 1):
                if pos in by_high:
                    chars = set()
                    for r in by_high[pos]:
                        c = (r['low'] + pos + offset) & 0xFF
                        if 32 <= c <= 126:
                            chars.add(chr(c))
                    if len(chars) == 1:
                        flag_str += list(chars)[0]
                    elif chars:
                        flag_str += f"[{''.join(sorted(chars))}]"
                    else:
                        flag_str += "."
                else:
                    flag_str += "?"
            print(f"\n  *** (LOW+POS+0x{offset:02X}) MATCHES! ***")
            print(f"  Flag: {flag_str}")
    
    print("\n" + "=" * 80)
    print(" APPROACH 8: VALUE MOD N = ASCII")
    print("=" * 80)
    
    # Try: value mod N = ASCII char, with high byte as position
    for N in [128, 100, 96, 64, 58, 48, 42, 256]:
        match = True
        for pos in range(len(target_chars)):
            expected = ord(target_chars[pos])
            if pos not in by_high:
                match = False
                break
            found = any(r['value'] % N == expected for r in by_high[pos])
            if not found:
                match = False
                break
        if match:
            flag_str = ""
            for pos in range(max(by_high.keys()) + 1):
                if pos in by_high:
                    chars = set()
                    for r in by_high[pos]:
                        c = r['value'] % N
                        if 32 <= c <= 126:
                            chars.add(chr(c))
                    if len(chars) == 1:
                        flag_str += list(chars)[0]
                    elif chars:
                        flag_str += f"[{''.join(sorted(chars))}]"
                    else:
                        flag_str += "."
                else:
                    flag_str += "?"
            print(f"\n  *** VALUE MOD {N} MATCHES! ***")
            print(f"  Flag: {flag_str}")
    
    print("\n" + "=" * 80)
    print(" APPROACH 9: GLOBAL SEARCH FOR 'donotecho' IN RAW PCAP")
    print("=" * 80)
    
    # Read raw file and search for flag patterns with various XOR keys
    with open(filepath, 'rb') as f:
        raw = f.read()
    
    flag_bytes = b"donotecho{"
    for key in range(256):
        xored = bytes([b ^ key for b in flag_bytes])
        pos = raw.find(xored)
        if pos >= 0:
            # Found! Extract surrounding bytes
            start = pos
            end = min(pos + 100, len(raw))
            decoded = bytes([b ^ key for b in raw[start:end]])
            text = decoded.decode('ascii', errors='replace')
            # Find the closing brace
            brace_pos = text.find('}')
            if brace_pos > 0:
                text = text[:brace_pos+1]
            print(f"\n  *** FOUND IN RAW PCAP! XOR key 0x{key:02X}, offset {pos} ***")
            print(f"  Flag: {text}")
    
    # Also search for base64-encoded flag
    for b64_variant in [
        base64.b64encode(b"donotecho{"),
        base64.b64encode(b"donotecho"),
    ]:
        pos = raw.find(b64_variant[:8])
        if pos >= 0:
            chunk = raw[pos:pos+200]
            try:
                decoded = base64.b64decode(chunk)
                print(f"\n  *** FOUND BASE64 at offset {pos} ***")
                print(f"  Decoded: {decoded.decode('utf-8', errors='replace')}")
            except:
                pass
    
    print("\n" + "=" * 80)
    print(" APPROACH 10: STATISTICS ON HIGH BYTES")
    print("=" * 80)
    
    # Show distribution of high bytes to understand the encoding
    print("\n  High byte distribution (positions):")
    for pos in sorted(by_high.keys()):
        low_vals = [r['low'] for r in by_high[pos]]
        low_hex = ' '.join(f'{v:02X}' for v in low_vals[:10])
        print(f"    Pos {pos:2d}: count={len(by_high[pos]):3d} | low bytes: {low_hex}{'...' if len(low_vals)>10 else ''}")
    
    # Check the MOST COMMON low byte at each position
    print("\n  Most common low byte at each position:")
    flag_by_mode = ""
    for pos in range(max(by_high.keys()) + 1):
        if pos in by_high:
            low_counts = {}
            for r in by_high[pos]:
                lo = r['low']
                low_counts[lo] = low_counts.get(lo, 0) + 1
            mode_lo = max(low_counts, key=low_counts.get)
            count = low_counts[mode_lo]
            total = len(by_high[pos])
            print(f"    Pos {pos:2d}: mode=0x{mode_lo:02X} ({count}/{total})")
            flag_by_mode += chr(mode_lo) if 32 <= mode_lo <= 126 else '.'
        else:
            flag_by_mode += "?"
    print(f"\n  Mode low bytes as ASCII: {flag_by_mode}")
    
    print("\n" + "=" * 80)
    print(" DONE")
    print("=" * 80)


if __name__ == "__main__":
    main()
