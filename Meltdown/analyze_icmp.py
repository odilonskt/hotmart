import re
try:
    from scapy.all import rdpcap, ICMP, Raw
except ImportError:
    print("A biblioteca 'scapy' não está instalada.")
    exit(1)

def analyze_icmp(file_path: str):
    print(f"[*] Procurando pacotes ICMP (Ping) em: {file_path}")
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"[-] Erro ao ler PCAP: {e}")
        return

    icmp_payloads = b""
    icmp_count = 0
    
    for pkt in packets:
        if pkt.haslayer(ICMP):
            icmp_count += 1
            # ICMP Type 8 é Echo Request (ping), Type 0 é Echo Reply
            # Vamos extrair os payloads de todos os ICMP
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                print(f"[+] Pacote ICMP ({pkt[ICMP].type}) extraído: {len(payload)} bytes")
                icmp_payloads += payload

    print(f"\n[*] Total de pacotes ICMP com dados encontrados: {icmp_count}")
    
    if icmp_count == 0:
        print("[-] Nenhum pacote ICMP encontrado.")
        return

    # Tenta achar a flag no payload concatenado
    flag_regex = b"donotecho\\{.*?\\}"
    matches = re.findall(flag_regex, icmp_payloads)
    for m in matches:
        print(f"\n[🏆] FLAG ENCONTRADA (Texto Claro em ICMP)! \n    -> {m.decode(errors='ignore')}")
        return

    # Tenta imprimir o que tem dentro do ICMP
    print("\n[-] A flag não foi achada de forma direta, mas veja o conteúdo dos pacotes ICMP:")
    clean_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in icmp_payloads)
    print(f"Dados ICMP brutos:\n{clean_text}")

if __name__ == '__main__':
    analyze_icmp(r'c:\Users\User\Desktop\Meltdown\industrial_meltdown.pcap')
