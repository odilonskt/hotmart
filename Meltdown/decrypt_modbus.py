import re
import binascii
try:
    from scapy.all import rdpcap, TCP, Raw
except ImportError:
    print("A biblioteca 'scapy' não está instalada.")
    exit(1)

def extract_and_decrypt(file_path: str):
    print(f"[*] Extraindo payload Modbus de {file_path}")
    packets = rdpcap(file_path)
    
    extracted_bytes = b""
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if pkt[TCP].sport == 502 or pkt[TCP].dport == 502:
                payload = pkt[Raw].load
                if len(payload) >= 8 and payload[2:4] == b'\x00\x00':
                    function_code = payload[7]
                    if function_code == 16 and len(payload) > 13:
                        extracted_bytes += payload[13:13+payload[12]]
                    elif function_code == 6 and len(payload) == 12:
                        extracted_bytes += payload[10:12]
                    elif (function_code == 3 or function_code == 4) and pkt[TCP].sport == 502 and len(payload) > 9:
                        extracted_bytes += payload[9:9+payload[8]]

    print(f"[+] Bytes extraídos: {len(extracted_bytes)}")
    
    # Vamos escrever em um arquivo para referência
    with open(r'c:\Users\User\Desktop\Meltdown\modbus_payload.bin', 'wb') as f:
        f.write(extracted_bytes)
        
    print("[*] Iniciando tentativa de Decriptografia (Known-Plaintext Attack / XOR)...")
    
    known_plain = b"donotecho{"
    found_key = False
    
    # 1. Tentar XOR de 1 Byte
    print("\n[*] Testando XOR de 1 byte (Brute-force 0-255)...")
    for key in range(256):
        decrypted = bytes([b ^ key for b in extracted_bytes])
        if known_plain in decrypted:
            print(f"\n[🏆] SUCESSO! Cifra XOR quebrada com a chave: {hex(key)}")
            matches = re.findall(b"donotecho\\{.*?\\}", decrypted)
            for m in matches:
                print(f"    -> Flag: {m.decode(errors='ignore')}")
            found_key = True
            break
            
    # 2. Tentar remover bytes nulos e tentar XOR de 1 byte de novo
    if not found_key:
        print("\n[*] Testando XOR de 1 byte sem null padding...")
        no_nulls = extracted_bytes.replace(b'\x00', b'')
        for key in range(256):
            decrypted = bytes([b ^ key for b in no_nulls])
            if known_plain in decrypted:
                print(f"\n[🏆] SUCESSO! XOR quebrado (sem padding) com a chave: {hex(key)}")
                matches = re.findall(b"donotecho\\{.*?\\}", decrypted)
                for m in matches:
                    print(f"    -> Flag: {m.decode(errors='ignore')}")
                found_key = True
                break

    # 3. Known Plaintext Attack para chaves XOR maiores
    if not found_key:
        print("\n[*] Testando XOR com chaves maiores (Known Plaintext Attack)...")
        # Deslizaremos 'donotecho{' pelos bytes brutos e sem nulos
        for data_variant in [extracted_bytes, no_nulls]:
            for i in range(len(data_variant) - len(known_plain)):
                chunk = data_variant[i:i+len(known_plain)]
                possible_key = bytes([c ^ k for c, k in zip(chunk, known_plain)])
                
                # Se a chave for repetitiva (ex: 'keykeykeyk'), o início será igual ao final
                # Vamos tentar aplicar a possível chave
                # Extraímos o menor padrão repetitivo da possible_key
                # Para simplificar, vamos imprimir se a chave for toda em texto legível (letras/números)
                is_ascii = all(32 <= b <= 126 for b in possible_key)
                if is_ascii and possible_key.count(possible_key[0]) < len(possible_key): 
                    # Não é só 1 byte repetido e é ascii legível
                    # Pode ser a chave! Vamos mostrar para análise visual se ela parecer uma palavra
                    # Como é muito ruidoso, mostraremos só se acharmos a flag inteira com ela
                    for key_len in range(2, 9): # Assume chave de até 8 bytes
                        short_key = possible_key[:key_len]
                        
                        # Decriptar usando a short_key
                        decrypted = bytearray(len(data_variant))
                        for j in range(len(data_variant)):
                            decrypted[j] = data_variant[j] ^ short_key[j % len(short_key)]
                        
                        if known_plain in decrypted:
                            print(f"\n[🏆] SUCESSO! Cifra XOR quebrada com a chave: '{short_key.decode(errors='ignore')}'")
                            matches = re.findall(b"donotecho\\{.*?\\}", decrypted)
                            for m in matches:
                                print(f"    -> Flag: {m.decode(errors='ignore')}")
                            found_key = True
                            return
                            
    if not found_key:
        print("\n[-] XOR básico falhou. O arquivo pode estar cifrado com algo como AES, Vigenère, ou codificado em Base32/58.")
        print("[!] Verifique o arquivo extraído em 'modbus_payload.bin' para análise com ferramentas como CyberChef.")

if __name__ == '__main__':
    extract_and_decrypt(r'c:\Users\User\Desktop\Meltdown\industrial_meltdown.pcap')
