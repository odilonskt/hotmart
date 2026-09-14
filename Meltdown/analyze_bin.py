import os
import binascii

def analyze_binary(file_path):
    if not os.path.exists(file_path):
        print(f"[-] Arquivo não encontrado: {file_path}")
        return
        
    with open(file_path, 'rb') as f:
        data = f.read()
        
    print(f"[*] Tamanho do arquivo: {len(data)} bytes")
    print(f"[*] Primeiros 32 bytes (Hex): {data[:32].hex()}")
    print(f"[*] Últimos 32 bytes (Hex): {data[-32:].hex()}")
    
    # Entropia de Shannon (mede o nível de criptografia/compressão)
    import math
    from collections import Counter
    entropy = -sum((count/len(data)) * math.log2(count/len(data)) for count in Counter(data).values())
    print(f"[*] Entropia de Shannon: {entropy:.2f} (Valores > 7.5 indicam compressão forte ou criptografia AES/RSA/etc)")

if __name__ == '__main__':
    analyze_binary(r'c:\Users\User\Desktop\Meltdown\modbus_payload.bin')
