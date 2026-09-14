import os
try:
    from scapy.all import rdpcap, TCP, UDP, IP, Raw
except ImportError:
    print("A biblioteca 'scapy' não está instalada.")
    exit(1)

def dump_all_streams(file_path: str, output_dir: str):
    print(f"[*] Extraindo TODOS os fluxos de dados de {file_path}")
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"[-] Erro ao ler PCAP: {e}")
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    streams = {}
    
    # 1. Agrupar por conexões TCP (incluindo as misteriosas portas 45000 e 45002)
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt.haslayer(Raw):
            # Ordenando IPs e portas para agrupar requisição e resposta no mesmo arquivo
            ep1 = f"{pkt[IP].src}_{pkt[TCP].sport}"
            ep2 = f"{pkt[IP].dst}_{pkt[TCP].dport}"
            stream_id = tuple(sorted([ep1, ep2]))
            
            if stream_id not in streams:
                streams[stream_id] = b""
            streams[stream_id] += pkt[Raw].load

    print(f"[+] Foram encontrados {len(streams)} fluxos bidirecionais de dados.")

    # 2. Salvar cada fluxo em um arquivo binário para análise manual ou de "magic bytes" (arquivos embutidos)
    for i, (stream_id, data) in enumerate(streams.items()):
        name = f"stream_{i}_{stream_id[0]}_to_{stream_id[1]}.bin"
        name = name.replace(":", "_")
        out_path = os.path.join(output_dir, name)
        with open(out_path, "wb") as f:
            f.write(data)
        
        # Checa assinaturas de arquivos conhecidos (Magic Bytes)
        file_type = "Desconhecido/Texto"
        if data.startswith(b"\x89PNG\r\n\x1a\n"): file_type = "Imagem PNG"
        elif data.startswith(b"PK\x03\x04"): file_type = "Arquivo ZIP"
        elif data.startswith(b"\xff\xd8\xff"): file_type = "Imagem JPEG"
        elif data.startswith(b"MZ"): file_type = "Executável Windows (EXE)"
        elif data.startswith(b"\x7fELF"): file_type = "Executável Linux (ELF)"
        elif data.startswith(b"%PDF"): file_type = "Documento PDF"
        
        print(f"    -> Salvo: {name} | Tamanho: {len(data)} bytes | Tipo Sugerido: {file_type}")

    print(f"\n[*] Todos os arquivos extraídos em: {output_dir}")
    print("[!] Dica: Verifique se algum dos arquivos parece ser um executável, ZIP ou imagem. A flag pode estar dentro de um arquivo transferido!")

if __name__ == '__main__':
    dump_all_streams(r'c:\Users\User\Desktop\Meltdown\industrial_meltdown.pcap', r'c:\Users\User\Desktop\Meltdown\streams')
