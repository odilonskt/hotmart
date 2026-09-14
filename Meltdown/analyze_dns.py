try:
    from scapy.all import rdpcap, DNS
    import base64
    import os

    files_to_check = ['c:/Users/User/Desktop/Meltdown/rebuilt_memory.bin', 'c:/Users/User/Desktop/Meltdown/modbus_payload.bin']
    
    for file_path in files_to_check:
        if not os.path.exists(file_path):
            continue
            
        print(f"\n[*] Analisando DNS em {file_path}")
        try:
            packets = rdpcap(file_path)
        except Exception as e:
            print(f"[-] Erro ao abrir pcap {file_path}: {e}")
            continue
            
        subdomains = []
        for pkt in packets:
            if pkt.haslayer(DNS) and pkt.qdcount > 0:
                qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                if 'crazycorpteam.com' in qname:
                    # extrai o subdominio
                    sub = qname.replace('.crazycorpteam.com.', '').replace('.crazycorpteam.com', '')
                    subdomains.append(sub)
        
        if not subdomains:
            print("[-] Nenhuma query DNS para crazycorpteam.com encontrada.")
            continue
            
        print(f"[+] Encontrados {len(subdomains)} subdomínios:")
        for sub in subdomains:
            print(f"    -> {sub}")
            
        # Tenta juntar e decodificar em Base32
        joined = "".join(subdomains).upper()
        # Remove caracteres que não são do base32
        joined = "".join(c for c in joined if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        print(f"\n[*] String concatenada (Base32): {joined}")
        
        # Pad string to multiple of 8
        padded = joined + "=" * ((8 - len(joined) % 8) % 8)
        
        try:
            decoded = base64.b32decode(padded).decode('utf-8', errors='ignore')
            print(f"[🏆] Possível Flag decodificada: {decoded}")
        except Exception as e:
            print(f"[-] Erro no decode Base32: {e}")

except ImportError:
    print("A biblioteca scapy não está instalada.")
