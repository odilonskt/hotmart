try:
    from scapy.all import rdpcap, TCP, Raw
except ImportError:
    print("A biblioteca 'scapy' não está instalada.")
    exit(1)

def rebuild_modbus_memory(file_path: str):
    print(f"[*] Analisando endereçamento de memória Modbus em: {file_path}")
    packets = rdpcap(file_path)
    
    # Dicionário para representar a memória do CLP
    # Mapeia Endereço_do_Registrador -> Valor (2 bytes)
    memory_map = {}
    
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if pkt[TCP].sport == 502 or pkt[TCP].dport == 502:
                payload = pkt[Raw].load
                
                if len(payload) >= 8 and payload[2:4] == b'\x00\x00':
                    function_code = payload[7]
                    
                    # Write Multiple Registers (Master escrevendo)
                    if function_code == 16 and len(payload) > 13:
                        ref_num = int.from_bytes(payload[8:10], byteorder='big')
                        word_count = int.from_bytes(payload[10:12], byteorder='big')
                        byte_count = payload[12]
                        register_values = payload[13:13+byte_count]
                        
                        # Cada registrador tem 2 bytes
                        for i in range(word_count):
                            reg_address = ref_num + i
                            reg_data = register_values[i*2:(i*2)+2]
                            memory_map[reg_address] = reg_data
                            
                    # Write Single Register (Master escrevendo)
                    elif function_code == 6 and len(payload) == 12:
                        ref_num = int.from_bytes(payload[8:10], byteorder='big')
                        reg_data = payload[10:12]
                        memory_map[ref_num] = reg_data

                    # Funções de leitura (Slave respondendo)
                    # O problema da resposta é que não temos o Endereço de Referência nela!
                    # Apenas no request. Para simplificar, vamos ver se a flag foi ESCRITA (funções 6 e 16).

    if not memory_map:
        print("[-] Nenhuma instrução de ESCRITA encontrada na memória.")
        return

    print(f"[+] Foram gravados dados em {len(memory_map)} registradores distintos.")
    
    # Vamos descobrir o menor e o maior endereço para montar o binário
    min_reg = min(memory_map.keys())
    max_reg = max(memory_map.keys())
    print(f"[*] Registradores gravados: do endereço {min_reg} ao {max_reg}")

    # Remontando o arquivo baseado nos ENDEREÇOS em vez da ordem dos pacotes
    rebuilt_bytes = bytearray((max_reg - min_reg + 1) * 2)
    
    for reg_addr, data in memory_map.items():
        offset = (reg_addr - min_reg) * 2
        rebuilt_bytes[offset:offset+2] = data
        
    print(f"[*] Tamanho do arquivo reconstruído ordenado pela memória: {len(rebuilt_bytes)} bytes")
    
    # Salva o arquivo remontado
    out_file = r'c:\Users\User\Desktop\Meltdown\rebuilt_memory.bin'
    with open(out_file, 'wb') as f:
        f.write(rebuilt_bytes)
    print(f"[+] Arquivo salvo em: {out_file}")

    # Verifica assinaturas / Strings
    import re
    flag_regex = b"donotecho\\{.*?\\}"
    matches = re.findall(flag_regex, rebuilt_bytes)
    if matches:
        print(f"\n[🏆] FLAG ENCONTRADA NA MEMÓRIA ORDENADA! \n    -> {matches[0].decode(errors='ignore')}")
    else:
        # Verifica sem nulos
        matches_no_null = re.findall(flag_regex, rebuilt_bytes.replace(b'\x00', b''))
        if matches_no_null:
            print(f"\n[🏆] FLAG ENCONTRADA NA MEMÓRIA (Padding Removido)! \n    -> {matches_no_null[0].decode(errors='ignore')}")
        else:
            print("\n[-] Flag não encontrada em texto claro após ordenar a memória.")
            print("[!] Rode o `analyze_bin.py` no `rebuilt_memory.bin` para ver se a entropia baixou ou se apareceram Magic Bytes!")

if __name__ == '__main__':
    rebuild_modbus_memory(r'c:\Users\User\Desktop\Meltdown\industrial_meltdown.pcap')
