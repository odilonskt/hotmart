import re
import binascii
try:
    from scapy.all import rdpcap, TCP, Raw
except ImportError:
    print("A biblioteca 'scapy' não está instalada.")
    exit(1)

def extract_modbus_flag(file_path: str):
    print(f"[*] Analisando tráfego Modbus TCP em: {file_path}")
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"[-] Erro ao ler PCAP: {e}")
        return

    extracted_bytes = b""
    
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            # Analisar apenas tráfego envolvendo a porta Modbus (502)
            if pkt[TCP].sport == 502 or pkt[TCP].dport == 502:
                payload = pkt[Raw].load
                
                # Verifica cabeçalho Modbus TCP (MBAP)
                # MBAP: [0:2] Trans ID, [2:4] Protocol (00 00), [4:6] Length, [6] Unit ID
                if len(payload) >= 8 and payload[2:4] == b'\x00\x00':
                    function_code = payload[7]
                    
                    # Função 16 (Write Multiple Registers): Escrita pelo Master
                    if function_code == 16 and len(payload) > 13:
                        byte_count = payload[12]
                        register_values = payload[13:13+byte_count]
                        extracted_bytes += register_values
                        
                    # Função 6 (Write Single Register): Escrita pelo Master
                    elif function_code == 6 and len(payload) == 12:
                        register_value = payload[10:12]
                        extracted_bytes += register_value

                    # Função 3 ou 4 (Read Registers - Resposta do Slave/PLC)
                    elif (function_code == 3 or function_code == 4) and pkt[TCP].sport == 502 and len(payload) > 9:
                        byte_count = payload[8]
                        register_values = payload[9:9+byte_count]
                        extracted_bytes += register_values

    if not extracted_bytes:
        print("[-] Nenhum dado Modbus útil foi extraído (nenhuma leitura/escrita de registradores encontrada).")
        return

    print(f"[+] Total de bytes extraídos dos registradores Modbus: {len(extracted_bytes)}")
    
    # Heurística 1: Flag concatenada diretamente nos bytes
    flag_regex = b"donotecho\{.*?\}"
    matches = re.findall(flag_regex, extracted_bytes)
    for m in matches:
        print(f"\n[🏆] FLAG ENCONTRADA (Sequência Direta)! \n    -> {m.decode(errors='ignore')}")
        return

    # Heurística 2: Flag em registradores de 16 bits (ex: 'd' = 0x00 0x64 ou 0x64 0x00)
    # Vamos remover todos os bytes nulos (\x00) da sequência e tentar achar a flag
    no_null_bytes = extracted_bytes.replace(b'\x00', b'')
    matches_no_null = re.findall(flag_regex, no_null_bytes)
    for m in matches_no_null:
        print(f"\n[🏆] FLAG ENCONTRADA (Lida de Registradores com Padding de Nulos)! \n    -> {m.decode(errors='ignore')}")
        return

    # Heurística 3: Base64 espalhado nos registradores (sem nulos)
    b64_regex = b"ZG9ub3RlY2hv[a-zA-Z0-9+/=]+"
    b64_matches = re.findall(b64_regex, no_null_bytes)
    for bm in b64_matches:
        try:
            import base64
            bm_padded = bm + b"=" * ((4 - len(bm) % 4) % 4)
            flag = base64.b64decode(bm_padded).decode('utf-8')
            if "donotecho{" in flag:
                print(f"\n[🏆] FLAG ENCONTRADA (Base64 em Registradores)! \n    -> {flag}")
                return
        except:
            pass
            
    # Heurística 4: Swap Bytes (Endianness). Em alguns PLCs, o byte mais significativo e o menos significativo são invertidos.
    swapped_bytes = bytearray()
    for i in range(0, len(extracted_bytes)-1, 2):
        swapped_bytes.append(extracted_bytes[i+1])
        swapped_bytes.append(extracted_bytes[i])
    
    matches_swapped = re.findall(flag_regex, swapped_bytes)
    for m in matches_swapped:
        print(f"\n[🏆] FLAG ENCONTRADA (Endianness Invertido)! \n    -> {m.decode(errors='ignore')}")
        return

    print("\n[-] Flag não encontrada. Vamos tentar imprimir os bytes extraídos como texto caso o Regex tenha falhado:")
    # Imprime tudo limpando caracteres não imprimíveis
    clean_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in extracted_bytes)
    print(f"Texto bruto (Modbus): {clean_text[:500]}...")

if __name__ == '__main__':
    extract_modbus_flag(r'c:\Users\User\Desktop\Meltdown\industrial_meltdown.pcap')
