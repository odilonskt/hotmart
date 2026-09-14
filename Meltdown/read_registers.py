try:
    from scapy.all import rdpcap, TCP, Raw
except ImportError:
    print("A biblioteca 'scapy' não está instalada.")
    exit(1)

def extract_ordered_registers(file_path: str):
    print(f"[*] Lendo registros gravados em: {file_path}")
    packets = rdpcap(file_path)
    
    memory_map = {}
    
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if pkt[TCP].sport == 502 or pkt[TCP].dport == 502:
                payload = pkt[Raw].load
                
                if len(payload) >= 8 and payload[2:4] == b'\x00\x00':
                    function_code = payload[7]
                    
                    if function_code == 16 and len(payload) > 13:
                        ref_num = int.from_bytes(payload[8:10], byteorder='big')
                        word_count = int.from_bytes(payload[10:12], byteorder='big')
                        byte_count = payload[12]
                        register_values = payload[13:13+byte_count]
                        for i in range(word_count):
                            memory_map[ref_num + i] = register_values[i*2:(i*2)+2]
                            
                    elif function_code == 6 and len(payload) == 12:
                        ref_num = int.from_bytes(payload[8:10], byteorder='big')
                        memory_map[ref_num] = payload[10:12]

    if not memory_map:
        print("[-] Nada encontrado.")
        return

    print(f"[+] Encontrados {len(memory_map)} registradores gravados.")
    
    # Ordena os registradores pelo endereço numérico
    sorted_regs = sorted(memory_map.items())
    
    print("\n[*] Conteúdo dos registradores ordenados por endereço:")
    
    ordered_bytes = b""
    for addr, val in sorted_regs:
        ordered_bytes += val
        print(f"    -> Reg {addr:04d}: {val.hex()} | Tenta texto: {val.replace(b'\\x00', b'').decode(errors='ignore')}")

    print("\n[*] Juntando todos os bytes ordenados:")
    # Removemos bytes nulos para facilitar a leitura caso a flag tenha sido gravada 1 char por registrador
    clean_text = ordered_bytes.replace(b'\x00', b'').decode(errors='ignore')
    print(f"Texto extraído: {clean_text}")

if __name__ == '__main__':
    extract_ordered_registers(r'c:\Users\User\Desktop\Meltdown\industrial_meltdown.pcap')
