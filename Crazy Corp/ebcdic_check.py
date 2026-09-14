import struct

def check_ebcdic():
    with open('industrial_meltdown.pcap', 'rb') as f:
        raw = f.read()
    
    # "donotecho" in EBCDIC
    target = bytes([0x84, 0x96, 0x95, 0x96, 0xA3, 0x85, 0x83, 0x88, 0x96])
    
    for key in range(256):
        xored = bytes([b ^ key for b in target])
        pos = raw.find(xored)
        if pos >= 0:
            print(f"FOUND EBCDIC with XOR 0x{key:02X} at {pos}")

if __name__ == "__main__":
    check_ebcdic()
