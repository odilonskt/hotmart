import struct
import binascii

def search_signatures():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    
    sigs = {
        b'\x89PNG\r\n\x1a\n': 'PNG',
        b'\xff\xd8\xff': 'JPEG',
        b'PK\x03\x04': 'ZIP',
        b'Rar!\x1a\x07': 'RAR',
        b'7z\xbc\xaf\x27\x1c': '7Z',
        b'%PDF': 'PDF',
        b'GIF87a': 'GIF',
        b'GIF89a': 'GIF',
        b'BM': 'BMP',
        b'ID3': 'MP3',
        b'OggS': 'OGG',
        b'fLaC': 'FLAC',
        b'RIFF': 'WAV/AVI',
        b'\x52\x61\x72\x21\x1A\x07\x00': 'RAR5'
    }
    
    found = []
    
    for sig, name in sigs.items():
        idx = data.find(sig)
        # Skip BM at the very beginning of the PCAP since PCAP magic is D4 C3 B2 A1
        while idx != -1:
            if name == 'BMP' and idx < 24: 
                idx = data.find(sig, idx + 1)
                continue
                
            found.append((name, idx))
            idx = data.find(sig, idx + 1)
            
    with open('signatures_found.txt', 'w') as f:
        f.write(f"Total size: {len(data)}\n")
        for name, idx in found:
            f.write(f"Found {name} at offset {idx} (0x{idx:X})\n")
            
    print("Signatures found saved to signatures_found.txt")

if __name__ == "__main__":
    search_signatures()
