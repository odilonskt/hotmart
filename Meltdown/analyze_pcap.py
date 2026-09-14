import argparse
import re
try:
    from scapy.all import rdpcap, Raw
except ImportError:
    print("A biblioteca 'scapy' não está instalada. Instale com: pip install scapy")
    exit(1)

def analyze_pcap(file_path: str, flag_pattern: str):
    """
    Analisa um arquivo PCAP iterando sobre seus pacotes em busca de um padrão de flag.
    Boa prática: usar bibliotecas dedicadas (Scapy/Pyshark) para evitar falsos positivos
    e permitir a montagem de fluxos (TCP streams) se necessário.
    """
    try:
        print(f"[*] Carregando pacotes de: {file_path}...")
        # rdpcap carrega tudo na memória. Para arquivos gigantes, prefira PcapReader
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print(f"[-] Arquivo não encontrado: {file_path}")
        return
    except Exception as e:
        print(f"[-] Erro ao carregar arquivo PCAP: {e}")
        return

    print(f"[+] Arquivo lido com sucesso. Total de pacotes: {len(packets)}")
    
    # Prepara a regex em formato de bytes para buscar nos payloads brutos (Raw)
    regex = re.compile(flag_pattern.encode('utf-8'))
    found_flags = set()

    for idx, pkt in enumerate(packets):
        # Em protocolos de rede SCADA, dados da aplicação geralmente ficam na camada Raw (TCP/UDP payload)
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            matches = regex.findall(payload)
            
            for match in matches:
                try:
                    # Tenta decodificar a flag encontrada para string legível
                    flag_str = match.decode('utf-8')
                    found_flags.add((idx + 1, flag_str))
                except UnicodeDecodeError:
                    pass
                    
    if found_flags:
        print("\n[+] Possíveis flags encontradas:")
        for pkt_num, flag in sorted(found_flags):
            print(f"    -> [Pacote {pkt_num}] {flag}")
    else:
        print("\n[-] Nenhuma flag encontrada em texto claro nos payloads (camada Raw).")
        print("\n[!] Dicas para CTF SCADA / Industrial:")
        print(" 1. Protocolos Industriais: Se for tráfego Modbus TCP (porta 502) ou S7comm (porta 102),")
        print("    a flag pode estar escondida como valores de registradores ou coils.")
        print(" 2. Fragmentação: A flag pode estar dividida ao longo de múltiplos pacotes em um fluxo TCP.")
        print("    (Neste caso, é recomendável extrair o 'TCP Stream' usando Wireshark ou Scapy).")
        print(" 3. Codificação: Verifique se os dados estão codificados em Hexadecimal, Base64 ou XOR.")

def main():
    parser = argparse.ArgumentParser(description="Script de análise de tráfego SCADA para CTF")
    parser.add_argument("-f", "--file", default=r"c:\Users\User\Desktop\Meltdown\industrial_meltdown.pcap", help="Caminho do PCAP")
    parser.add_argument("-p", "--pattern", default=r"donotecho\{.*?\}", help="Padrão de Regex da Flag")
    
    args = parser.parse_args()
    analyze_pcap(args.file, args.pattern)

if __name__ == "__main__":
    main()
