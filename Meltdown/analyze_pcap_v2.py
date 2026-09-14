import re
import binascii
import base64
from collections import Counter
try:
    from scapy.all import rdpcap, TCP, UDP, IP, Raw
except ImportError:
    print("A biblioteca 'scapy' não está instalada. Instale com: pip install scapy")
    exit(1)

def analyze_advanced(file_path: str):
    print(f"[*] Carregando pacotes de: {file_path}...")
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"[-] Erro ao carregar: {e}")
        return

    print(f"[+] Total de pacotes: {len(packets)}")
    
    # Resumo de Portas para identificar Protocolos
    ports = Counter()
    for pkt in packets:
        if pkt.haslayer(TCP):
            ports[pkt[TCP].sport] += 1
            ports[pkt[TCP].dport] += 1
        elif pkt.haslayer(UDP):
            ports[pkt[UDP].sport] += 1
            ports[pkt[UDP].dport] += 1
            
    print("\n[*] Portas mais utilizadas (Possíveis protocolos industriais):")
    for port, count in ports.most_common(3):
        proto_name = "Desconhecido"
        if port == 502: proto_name = "Modbus TCP"
        elif port == 102: proto_name = "S7comm (Siemens)"
        elif port == 44818: proto_name = "EtherNet/IP"
        print(f"    -> Porta {port} ({proto_name}): {count} pacotes")

    print("\n[*] Analisando fluxos (TCP Streams) e codificações...")
    # Montar TCP Streams (agrupando por IP e Porta Origem/Destino)
    streams = {}
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt.haslayer(Raw):
            # Identificador direcional para não misturar requisição e resposta
            stream_id = f"{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}"
            if stream_id not in streams:
                streams[stream_id] = b""
            streams[stream_id] += pkt[Raw].load

    print(f"[+] {len(streams)} fluxos TCP de dados remontados.")

    flag_pattern = b"donotecho{.*?}"
    hex_regex = b"646f6e6f746563686f7b.*?7d" # 'donotecho{.*?}' em Hex
    b64_regex = b"ZG9ub3RlY2hv[a-zA-Z0-9+/=]+" # Base64 de 'donotecho'

    found = False
    
    for stream_id, data in streams.items():
        # 1. Busca no payload remontado (fragmentação TCP)
        matches = re.findall(flag_pattern, data)
        for m in matches:
            print(f"\n[!] FLAG ENCONTRADA (Texto Claro / Fragmentada) no fluxo:\n    {stream_id}")
            print(f"    -> {m.decode(errors='ignore')}")
            found = True
            
        # 2. Busca Hexadecimal (ex: enviados como bytes brutos Modbus)
        hex_data = binascii.hexlify(data)
        if b"646f6e6f746563686f7b" in hex_data:
            hex_matches = re.findall(hex_regex, hex_data)
            for hm in hex_matches:
                try:
                    flag = binascii.unhexlify(hm).decode('utf-8')
                    print(f"\n[!] FLAG ENCONTRADA (Codificação Hexadecimal) no fluxo:\n    {stream_id}")
                    print(f"    -> {flag}")
                    found = True
                except:
                    pass
                    
        # 3. Busca Base64
        if b"ZG9ub3RlY2hv" in data:
            b64_matches = re.findall(b64_regex, data)
            for bm in b64_matches:
                try:
                    # Adiciona padding se necessário
                    bm_padded = bm + b"=" * ((4 - len(bm) % 4) % 4)
                    flag = base64.b64decode(bm_padded).decode('utf-8')
                    if "donotecho{" in flag:
                        print(f"\n[!] FLAG ENCONTRADA (Codificação Base64) no fluxo:\n    {stream_id}")
                        print(f"    -> {flag}")
                        found = True
                except:
                    pass

    if not found:
        print("\n[-] A flag ainda não foi encontrada com as decodificações básicas.")
        print("[!] Próximo passo: A flag pode estar espalhada byte a byte em múltiplos pacotes Modbus (Read/Write Registers).")

if __name__ == '__main__':
    analyze_advanced(r'c:\Users\User\Desktop\Meltdown\industrial_meltdown.pcap')
