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
    '-.--.': '(', '-.--.-': ')', '-.-.--': '!', '.--.-.': '@'
}

def decode_morse():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    offset = 24
    
    SCADA = "192.168.100.20"
    reg_map = defaultdict(dict)
    requests = {}
    
    while offset < len(data) - 16:
        incl_len = struct.unpack(endian + 'I', data[offset+8:offset+12])[0]
        pkt = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(pkt) > 54 and struct.unpack('>H', pkt[12:14])[0] == 0x0800:
            ip = pkt[14:]
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
                                for i in range(0, bc, 2):
                                    if i + 1 < bc:
                                        val = struct.unpack('>H', reg_bytes[i:i+2])[0]
                                        reg_map[uid][start_reg + i//2] = val
                                        
    for uid, regs in reg_map.items():
        if len(regs) < 10: continue
        
        sorted_addrs = sorted(regs.keys())
        bits = []
        for addr in sorted_addrs:
            val = regs[addr]
            for b in range(16):
                bits.append((val >> (15 - b)) & 1)
                
        # Parse Morse Code
        # We need to find the unit size. It might be 1 bit, 2 bits, etc.
        # Let's count consecutive 1s and 0s
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
        
        # Find the smallest run of 1s to determine the time unit
        ones = [count for b, count in runs if b == 1]
        if not ones: continue
        unit_len = min(ones)
        
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
                if units >= 3 and units < 7:
                    # End of character
                    if current_char:
                        morse_chars.append(current_char)
                        current_char = ""
                elif units >= 7:
                    # End of word
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
            
        print(f"Unit {uid} Morse Decoded:\n{decoded}\n")

if __name__ == "__main__":
    decode_morse()
