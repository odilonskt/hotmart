import struct
from collections import defaultdict

MORSE_CODE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9', '-----': '0', '--..--': ', ',
    '.-.-.-': '.', '..--..': '?', '-..-.': '/', '-....-': '-',
    '-.--.': '(', '-.--.-': ')', '-.-.--': '!', '.--.-.': '@',
    '..--.-': '_'
}

def decode_lsb_morse():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    snaplen = struct.unpack(f'{endian}I', data[16:20])[0]
    offset = 24
    
    SCADA = "192.168.100.20"
    requests = {}
    responses = []
    
    while offset < len(data) - 16:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', data[offset:offset+16])
        if incl_len > snaplen or incl_len > len(data) - offset - 16: break
        raw = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(raw) > 54 and struct.unpack('>H', raw[12:14])[0] == 0x0800:
            ip = raw[14:]
            if len(ip) > 20 and ip[9] == 6:
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
                            requests[tid] = struct.unpack('>H', payload[8:10])[0]
                            
                        elif src_port == 502 and fc == 3 and len(payload) >= 9:
                            bc = payload[8]
                            start_reg = requests.get(tid, -1)
                            if dst_ip == SCADA and start_reg >= 0 and len(payload) >= 9 + bc:
                                reg_bytes = payload[9:9+bc]
                                values = []
                                for i in range(0, bc, 2):
                                    if i + 1 < bc:
                                        values.append(struct.unpack('>H', reg_bytes[i:i+2])[0])
                                responses.append((ts_sec + ts_usec / 1e6, uid, start_reg, values))

    responses.sort()
    
    bits = []
    for ts, uid, sreg, values in responses:
        for val in values:
            bits.append(val & 1)
            
    print(f"Total extracted LSB bits: {len(bits)}")
    print("Bits:", "".join(str(b) for b in bits[:200]), "...")
    
    # Run-length encoding
    runs = []
    current_bit = bits[0]
    count = 0
    for b in bits:
        if b == current_bit:
            count += 1
        else:
            runs.append((current_bit, count))
            current_bit = b
            count = 1
    runs.append((current_bit, count))
    
    print("Runs:", runs[:20])
    
    # Guess unit_len from '1's
    ones = [c for b, c in runs if b == 1]
    if not ones: return
    unit_len = min(ones)
    print(f"Unit length guessed as: {unit_len}")
    
    morse_chars = []
    current_char = ""
    for b, count in runs:
        units = round(count / unit_len)
        if b == 1:
            if units == 1:
                current_char += "."
            elif units >= 3:
                current_char += "-"
        else:
            if 2 <= units <= 5:
                if current_char:
                    morse_chars.append(current_char)
                    current_char = ""
            elif units > 5:
                if current_char:
                    morse_chars.append(current_char)
                    current_char = ""
                morse_chars.append(" ")
                
    if current_char:
        morse_chars.append(current_char)
        
    decoded = ""
    for m in morse_chars:
        if m == " ": decoded += " "
        else: decoded += MORSE_CODE_DICT.get(m, "?")
        
    print(f"Decoded Morse:\n{decoded}")

if __name__ == "__main__":
    decode_lsb_morse()
