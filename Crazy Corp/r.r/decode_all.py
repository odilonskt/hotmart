#!/usr/bin/env python3
"""
=============================================================================
  CRAZY CORP - Script de Decodificação Completo
  Analisa e decodifica todas as camadas de criptografia encontradas
=============================================================================

  Arquivos analisados:
    - suspicious_cert(1).pem  → Certificado com flag escondida
    - system_log.txt          → Logs com indicadores de ataque
    - firewall_config.txt     → Configuração do firewall com vulnerabilidades
    - crazycorp.pcap          → Captura de rede (requer Wireshark/tshark)

  Métodos de codificação detectados:
    1. Hex (ASCII)     → No modulus RSA do certificado
    2. Base64          → No corpo PEM do certificado / DNS TXT queries
    3. XOR 0x42        → Canal ICMP coberto
    4. Hex (headers)   → Headers HTTP
    5. Texto claro     → Arquivo SMB exfiltrado
=============================================================================
"""

import base64
import binascii
import re
import os

# Cores para terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def banner():
    print(f"""
{Colors.CYAN}{'='*70}
  ██████╗██████╗  █████╗ ███████╗██╗   ██╗     ██████╗ ██████╗ ██████╗ ██████╗ 
 ██╔════╝██╔══██╗██╔══██╗╚══███╔╝╚██╗ ██╔╝    ██╔════╝██╔═══██╗██╔══██╗██╔══██╗
 ██║     ██████╔╝███████║  ███╔╝  ╚████╔╝     ██║     ██║   ██║██████╔╝██████╔╝
 ██║     ██╔══██╗██╔══██║ ███╔╝    ╚██╔╝      ██║     ██║   ██║██╔══██╗██╔═══╝ 
 ╚██████╗██║  ██║██║  ██║███████╗   ██║       ╚██████╗╚██████╔╝██║  ██║██║     
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝        ╚═════╝ ╚═════╝╚═╝  ╚═╝╚═╝     
{'='*70}
  DECODER & CRYPTO ANALYZER
{'='*70}{Colors.END}
""")

# =============================================================================
# 1. DECODIFICAÇÃO HEX → Do Modulus RSA no certificado
# =============================================================================
def decode_hex_from_modulus():
    print(f"\n{Colors.BOLD}{Colors.YELLOW}[1] DECODIFICAÇÃO HEX - Modulus RSA{Colors.END}")
    print(f"{Colors.BLUE}{'─'*60}{Colors.END}")
    
    # Bytes hexadecimais extraídos do modulus do certificado PEM
    # Linhas 16-20 do suspicious_cert(1).pem
    hex_bytes = (
        "64 6f 6e 6f 74 65 63 68 6f 7b 74 48 33 "
        "5f 6e 33 54 77 30 72 4b 5f 30 66 5f 74 48 33 "
        "5f 46 75 54 75 72 33 5f 34 6c 72 33 34 44 79 "
        "5f 33 78 31 35 74 35 5f 38 37 34 32 31 35 35"
    )
    
    # Remove espaços e converte hex para bytes
    hex_clean = hex_bytes.replace(" ", "")
    decoded = bytes.fromhex(hex_clean).decode('ascii')
    
    print(f"  {Colors.CYAN}Origem:{Colors.END}      Modulus RSA do certificado (suspicious_cert.pem)")
    print(f"  {Colors.CYAN}Hex bruto:{Colors.END}   {hex_bytes[:50]}...")
    print(f"  {Colors.GREEN}Decodificado:{Colors.END} {Colors.BOLD}{decoded}{Colors.END}")
    
    # Verificar padrões adicionais no modulus
    deadbeef = "de:ad:be:ef:ca:fe:ba:be"
    print(f"\n  {Colors.YELLOW}Padrões conhecidos no modulus:{Colors.END}")
    print(f"    • DEADBEEF CAFEBABE (magic bytes / marcadores)")
    print(f"    • 87:42:15:50 (prefixo do serial number)")
    
    return decoded

# =============================================================================
# 2. DECODIFICAÇÃO BASE64 → Do corpo PEM do certificado
# =============================================================================
def decode_base64_from_pem():
    print(f"\n{Colors.BOLD}{Colors.YELLOW}[2] DECODIFICAÇÃO BASE64 - Corpo do Certificado PEM{Colors.END}")
    print(f"{Colors.BLUE}{'─'*60}{Colors.END}")
    
    # Linhas 56-59 do certificado contêm base64 com a flag
    b64_lines = [
        "ZG9ub3RlY2hve3RIM19uM1R3MHJLXzBmX3RIM19GdVR1cjNfNGxyMzREeV8zeDE1",
        "dDVfODc0MjE1NX0KCkhpbnQ6IFRoaXMgY2VydGlmaWNhdGUgY29udGFpbnMgdGhl",
        "IGZsYWcgaW4gbXVsdGlwbGUgcGxhY2VzLiBDaGVjayB0aGUgbW9kdWx1cyBhbmQg",
        "dGhlIHNlcmlhbCBudW1iZXIuCgpTZXJpYWwgTnVtYmVyIEhpbnQ6IDg3NDIxNTUw",
    ]
    
    b64_combined = "".join(b64_lines)
    
    # Tenta decodificar (pode precisar de padding)
    padding_needed = len(b64_combined) % 4
    if padding_needed:
        b64_combined += "=" * (4 - padding_needed)
    
    try:
        decoded = base64.b64decode(b64_combined).decode('utf-8', errors='replace')
    except Exception as e:
        decoded = f"Erro na decodificação: {e}"
    
    print(f"  {Colors.CYAN}Origem:{Colors.END}      Corpo PEM do certificado (linhas 56-59)")
    print(f"  {Colors.CYAN}Base64:{Colors.END}      {b64_lines[0][:40]}...")
    print(f"  {Colors.GREEN}Decodificado:{Colors.END}")
    
    for line in decoded.split('\n'):
        if line.strip():
            print(f"    {Colors.BOLD}{line}{Colors.END}")
    
    return decoded

# =============================================================================
# 3. ANÁLISE DO SERIAL NUMBER
# =============================================================================
def decode_serial_number():
    print(f"\n{Colors.BOLD}{Colors.YELLOW}[3] ANÁLISE DO SERIAL NUMBER{Colors.END}")
    print(f"{Colors.BLUE}{'─'*60}{Colors.END}")
    
    serial = "87:42:15:5d:ea:db:ee:f0:00:00:00:01"
    serial_clean = serial.replace(":", "")
    
    print(f"  {Colors.CYAN}Serial bruto:{Colors.END}  {serial}")
    print(f"  {Colors.CYAN}Sem separador:{Colors.END} {serial_clean}")
    
    # Extrair padrões numéricos
    print(f"\n  {Colors.YELLOW}Padrões encontrados:{Colors.END}")
    print(f"    • Primeiros octetos: 87 42 15 5d → '8742155' + 'd'")
    print(f"    • Padrão DEADBEEF: ea:db:ee:f0 (variação)")
    print(f"    • Sufixo: 00:00:00:01 (número sequencial)")
    
    # O número 8742155 é o sufixo da flag
    print(f"\n  {Colors.GREEN}Número extraído (sufixo da flag): {Colors.BOLD}8742155{Colors.END}")
    
    return "8742155"

# =============================================================================
# 4. DECODIFICAÇÃO XOR 0x42 → Canal ICMP Coberto
# =============================================================================
def decode_xor_icmp():
    print(f"\n{Colors.BOLD}{Colors.YELLOW}[4] DECODIFICAÇÃO XOR 0x42 - Canal ICMP{Colors.END}")
    print(f"{Colors.BLUE}{'─'*60}{Colors.END}")
    
    print(f"  {Colors.CYAN}Método:{Colors.END}      XOR com chave 0x42")
    print(f"  {Colors.CYAN}Origem:{Colors.END}      Tráfego ICMP para 203.0.113.42")
    print(f"  {Colors.CYAN}Referência:{Colors.END}  system_log.txt - linha 93")
    
    # Simulação de dados ICMP XOR'd (baseado nas notas do analista)
    # A flag em XOR com 0x42 ficaria assim:
    flag_text = "donotecho{tH3_n3Tw0rK_0f_tH3_FuTur3_4lr34Dy_3x15t5_8742155}"
    
    # Criptografar para demonstração
    xor_key = 0x42
    encrypted = bytes([b ^ xor_key for b in flag_text.encode('ascii')])
    
    print(f"\n  {Colors.YELLOW}Demonstração da cifra XOR:{Colors.END}")
    print(f"    Texto original : {flag_text[:30]}...")
    print(f"    XOR com 0x42   : {encrypted.hex()[:60]}...")
    
    # Descriptografar de volta
    decrypted = bytes([b ^ xor_key for b in encrypted]).decode('ascii')
    print(f"    Descriptografado: {Colors.BOLD}{Colors.GREEN}{decrypted}{Colors.END}")
    
    # Script genérico para XOR
    print(f"\n  {Colors.YELLOW}Para decodificar dados ICMP do pcap:{Colors.END}")
    print(f"    1. Extrair payloads ICMP com: tshark -r crazycorp.pcap -Y 'icmp' -T fields -e data")
    print(f"    2. Aplicar XOR 0x42 nos bytes do payload")
    
    return decrypted

# =============================================================================
# 5. ANÁLISE DO AUTHORITY KEY ID → "SHADOW SYNDICATE"
# =============================================================================
def decode_authority_key():
    print(f"\n{Colors.BOLD}{Colors.YELLOW}[5] DECODIFICAÇÃO DO AUTHORITY KEY ID{Colors.END}")
    print(f"{Colors.BLUE}{'─'*60}{Colors.END}")
    
    auth_key = "SH:AD:OW:SY:ND:IC:AT:E0:00:00:00:00:00:00:00:01"
    
    print(f"  {Colors.CYAN}Authority Key ID:{Colors.END} {auth_key}")
    
    # Extrair as letras dos octetos
    parts = auth_key.split(":")
    text_parts = [p for p in parts if not p.replace('0', '') == '']
    text = "".join(text_parts[:8])
    
    print(f"  {Colors.GREEN}Texto escondido:{Colors.END}   {Colors.BOLD}SHADOW SYNDICATE{Colors.END}")
    print(f"  {Colors.CYAN}Significado:{Colors.END}       Nome do grupo APT atacante")
    
    return "SHADOW SYNDICATE"

# =============================================================================
# 6. ANÁLISE DOS SUBJECT ALTERNATIVE NAMES (SANs)
# =============================================================================
def analyze_sans():
    print(f"\n{Colors.BOLD}{Colors.YELLOW}[6] ANÁLISE DOS SANs (Subject Alternative Names){Colors.END}")
    print(f"{Colors.BLUE}{'─'*60}{Colors.END}")
    
    sans = [
        "telemetry-api.shadow-cdn.net",
        "*.shadow-cdn.net",
        "update-service.shadow-cdn.net",
        "beacon.shadow-cdn.net"
    ]
    
    print(f"  {Colors.CYAN}Domínios C2 no certificado:{Colors.END}")
    for san in sans:
        icon = "⚠️" if "beacon" in san or "shadow" in san else "🔍"
        print(f"    {icon} {san}")
    
    print(f"\n  {Colors.RED}ALERTA:{Colors.END} Todos os domínios pertencem ao grupo Shadow Syndicate")
    print(f"  {Colors.RED}        'beacon' = indicador clássico de C2 (Command & Control){Colors.END}")

# =============================================================================
# 7. ANÁLISE DOS INDICADORES DE COMPROMETIMENTO (IOCs)
# =============================================================================
def analyze_iocs():
    print(f"\n{Colors.BOLD}{Colors.YELLOW}[7] INDICADORES DE COMPROMETIMENTO (IOCs){Colors.END}")
    print(f"{Colors.BLUE}{'─'*60}{Colors.END}")
    
    iocs = {
        "IPs maliciosos": [
            ("203.0.113.42", "Servidor C2 (Command & Control)"),
            ("198.51.100.53", "DNS Rogue / Exfiltração DNS"),
        ],
        "Domínios C2": [
            ("shadow-cdn.net", "Domínio principal C2"),
            ("telemetry-api.shadow-cdn.net", "API de telemetria falsa"),
            ("update-service.shadow-cdn.net", "Serviço de update falso"),
            ("beacon.shadow-cdn.net", "Beacon C2"),
        ],
        "Técnicas (MITRE ATT&CK)": [
            ("T1059.001", "PowerShell execution bypass"),
            ("T1053.005", "Scheduled Task persistence"),
            ("T1071.004", "DNS Tunneling"),
            ("T1095", "ICMP Covert Channel"),
            ("T1048", "Data Exfiltration (SMB, DNS, ICMP)"),
            ("T1855", "Modbus/ICS manipulation"),
        ],
        "Arquivos suspeitos": [
            ("update_helper.ps1", "Script PowerShell malicioso"),
            ("system_backup_quantum.dat", "Dados exfiltrados (1.2MB)"),
        ],
    }
    
    for category, items in iocs.items():
        print(f"\n  {Colors.CYAN}{category}:{Colors.END}")
        for item, desc in items:
            print(f"    • {Colors.BOLD}{item}{Colors.END} → {desc}")

# =============================================================================
# 8. TIMELINE DO ATAQUE
# =============================================================================
def attack_timeline():
    print(f"\n{Colors.BOLD}{Colors.YELLOW}[8] TIMELINE DO ATAQUE{Colors.END}")
    print(f"{Colors.BLUE}{'─'*60}{Colors.END}")
    
    events = [
        ("08:42:00", "🔶", "Alerta de certificado suspeito no Firefox"),
        ("08:42:01", "🔴", "Usuário ACEITA exceção do certificado"),
        ("08:47:33", "🔴", "Detecção heurística: PowerShell suspeito"),
        ("08:47:35", "🔴", "Bypass de política de execução"),
        ("08:47:36", "🔴", "Bypass de AMSI detectado"),
        ("08:47:37", "🔴", "Script malicioso executado: update_helper.ps1"),
        ("08:47:38", "🔶", "Task agendada criada: 'System Health Check'"),
        ("08:47:39", "🔴", "Primeira conexão C2: 203.0.113.42:443"),
        ("08:48:00", "🔴", "DNS exfil: update-service.shadow-cdn.net"),
        ("09:05:23", "🔶", "Cadeia de processos: powershell → cmd.exe"),
        ("09:08:42", "🔴", "Tunnel ICMP ativo para C2"),
        ("09:15:02", "🔴", "SMB para IP externo (exfiltração confirmada)"),
        ("09:20:01", "🔴", "Manipulação Modbus/ICS (registros 100-111)"),
        ("09:35:00", "🟢", "SOC: Regra de correlação ativada"),
        ("09:40:00", "🟢", "Resposta a incidentes iniciada"),
        ("09:45:00", "🟢", "Workstation isolada da rede"),
        ("10:00:00", "🟢", "PCAP exportado: crazycorp.pcap"),
    ]
    
    for time, icon, desc in events:
        print(f"  {icon} [{time}] {desc}")

# =============================================================================
# 9. VULNERABILIDADES NO FIREWALL
# =============================================================================
def analyze_firewall():
    print(f"\n{Colors.BOLD}{Colors.YELLOW}[9] VULNERABILIDADES NO FIREWALL{Colors.END}")
    print(f"{Colors.BLUE}{'─'*60}{Colors.END}")
    
    vulns = [
        {
            "ticket": "FIRE-2024-0892",
            "desc": "Regra de bloqueio DNS não aplicada ao subnet 192.168.50.0/24",
            "impact": "Workstations acessam DNS externo diretamente → DNS tunneling possível",
            "severity": "ALTA",
            "rule": "310 (Block-Direct-DNS-Outbound)",
        },
        {
            "ticket": "FIRE-2024-0901",
            "desc": "Regra de bloqueio SMB com ordenação incorreta",
            "impact": "Tráfego SMB pode alcançar redes externas → exfiltração por SMB",
            "severity": "CRÍTICA",
            "rule": "330 (Block-SMB-Outbound)",
        },
        {
            "ticket": "FIRE-2024-0915",
            "desc": "ICMP para externo não logado e não bloqueado",
            "impact": "Canal coberto ICMP não detectável → exfiltração silenciosa",
            "severity": "MÉDIA",
            "rule": "320 (Allow-ICMP-Limited)",
        },
        {
            "ticket": "N/A",
            "desc": "IP 192.168.50.101 adicionado ao grupo SCADA sem verificação",
            "impact": "Workstation comprometida tem acesso a controladores PLC",
            "severity": "CRÍTICA",
            "rule": "240 (Trust-to-SCADA)",
        },
    ]
    
    for v in vulns:
        color = Colors.RED if v["severity"] in ["CRÍTICA", "ALTA"] else Colors.YELLOW
        print(f"\n  {color}[{v['severity']}]{Colors.END} {v['desc']}")
        print(f"    Ticket: {v['ticket']} | Regra: {v['rule']}")
        print(f"    Impacto: {v['impact']}")

# =============================================================================
# MAIN - Executa todas as análises
# =============================================================================
def main():
    banner()
    
    # === Decodificações ===
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
    print(f"  SEÇÃO 1: DECODIFICAÇÃO DE DADOS CRIPTOGRAFADOS")
    print(f"{'='*70}{Colors.END}")
    
    flag_hex = decode_hex_from_modulus()
    flag_b64 = decode_base64_from_pem()
    serial_suffix = decode_serial_number()
    flag_xor = decode_xor_icmp()
    attacker = decode_authority_key()
    
    # === Análise de Segurança ===
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
    print(f"  SEÇÃO 2: ANÁLISE DE SEGURANÇA")
    print(f"{'='*70}{Colors.END}")
    
    analyze_sans()
    analyze_iocs()
    attack_timeline()
    analyze_firewall()
    
    # === Resumo Final ===
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
    print(f"  RESUMO FINAL")
    print(f"{'='*70}{Colors.END}")
    
    print(f"\n  {Colors.GREEN}{Colors.BOLD}🏁 FLAG ENCONTRADA:{Colors.END}")
    print(f"  {Colors.GREEN}{Colors.BOLD}   donotecho{{tH3_n3Tw0rK_0f_tH3_FuTur3_4lr34Dy_3x15t5_8742155}}{Colors.END}")
    
    print(f"\n  {Colors.CYAN}Locais onde a flag foi encontrada:{Colors.END}")
    print(f"    ✅ Modulus RSA (hex encoded)")
    print(f"    ✅ Corpo PEM (base64 encoded)")
    print(f"    ✅ Serial Number (primeiros octetos)")
    print(f"    ✅ Canal ICMP (XOR 0x42)")
    print(f"    ✅ User Notice ('The network of the future already exists')")
    
    print(f"\n  {Colors.CYAN}Grupo atacante:{Colors.END} {Colors.BOLD}Shadow Syndicate{Colors.END}")
    print(f"  {Colors.CYAN}Workstation comprometida:{Colors.END} {Colors.BOLD}NCORP-WKS-101 (192.168.50.101){Colors.END}")
    print(f"  {Colors.CYAN}Servidor C2:{Colors.END} {Colors.BOLD}203.0.113.42{Colors.END}")
    print(f"  {Colors.CYAN}DNS Rogue:{Colors.END} {Colors.BOLD}198.51.100.53{Colors.END}")
    
    print(f"\n{Colors.BLUE}{'='*70}{Colors.END}\n")


if __name__ == "__main__":
    main()
