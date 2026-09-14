#!/usr/bin/env python3
"""
Analisador de logs CTF - Triangulation
Procura por padrões suspeitos em app.log, nginx.log e syslog
"""
import json
import re
from urllib.parse import unquote
from collections import defaultdict, Counter

# ─── APP.LOG ───────────────────────────────────────────────────────────────────
print("=" * 80)
print("ANÁLISE: app.log")
print("=" * 80)

app_log_path = "app.log"
app_entries = []
app_errors = []
app_unusual_messages = []
req_refs = []

with open(app_log_path, "r", encoding="utf-8", errors="ignore") as f:
    content = f.read()

# Extract req_refs from stack traces (hex values)
refs = re.findall(r'req_ref: (0x[0-9a-fA-F]+)', content)
print(f"\n[req_refs encontrados] Total: {len(refs)}")
if refs:
    for r in refs[:20]:
        val = int(r, 16)
        char_val = val & 0xFF  # lower byte
        print(f"  {r} -> decimal: {val} -> char: {chr(char_val) if 32 <= char_val <= 126 else '?'} -> bytes: {val.to_bytes((val.bit_length()+7)//8, 'big')}")

# Parse entries
lines = content.split('\n')
messages = []
services = defaultdict(list)
levels = defaultdict(int)

for line in lines:
    line = line.strip()
    if not line or line.startswith('{') is False:
        continue
    try:
        obj = json.loads(line)
        msg = obj.get('message', '')
        svc = obj.get('service', '')
        lvl = obj.get('level', '')
        ts = obj.get('timestamp', '')
        messages.append(msg)
        services[svc].append({'level': lvl, 'message': msg, 'timestamp': ts})
        levels[lvl] += 1
        if 'stack_trace' in obj:
            app_errors.append(obj)
    except:
        pass

print(f"\n[Níveis de log]")
for k, v in sorted(levels.items(), key=lambda x: -x[1]):
    print(f"  {k}: {v}")

print(f"\n[Mensagens únicas]")
msg_counter = Counter(messages)
for msg, cnt in msg_counter.most_common():
    print(f"  ({cnt:4d}x) {msg}")

print(f"\n[Mensagens incomuns/únicas - possíveis pistas]")
unique_msgs = [m for m, c in msg_counter.items() if c <= 3]
for m in unique_msgs:
    print(f"  -> {m}")

# Check if req_refs might encode something
if refs:
    print("\n[Tentativa de decodificação dos req_refs como ASCII]")
    hex_vals = [int(r, 16) for r in refs]
    # Cada valor como caractere (último byte)
    chars_low = ''.join(chr(v & 0xFF) if 32 <= (v & 0xFF) <= 126 else '.' for v in hex_vals)
    # Como bytes diretos se couber
    chars_direct = ''.join(chr(v) if 32 <= v <= 126 else '.' for v in hex_vals)
    print(f"  Byte baixo de cada ref: {chars_low}")
    print(f"  Valor direto como char: {chars_direct}")
    
    # Tenta interpretar pares de bytes
    print("\n[Req_refs em hex bruto]")
    print("  " + " ".join(refs[:30]))

# ─── NGINX.LOG ────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("ANÁLISE: nginx.log")
print("=" * 80)

nginx_path = "nginx.log"
nginx_entries = []
status_codes = defaultdict(int)
ips = defaultdict(int)
endpoints = defaultdict(int)
suspicious_urls = []

nginx_pattern = re.compile(
    r'^(\S+) - - \[([^\]]+)\] "(\S+) (\S+) HTTP/[^"]+" (\d{3}) (\d+)'
)

with open(nginx_path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        m = nginx_pattern.match(line.strip())
        if m:
            ip, ts, method, url, status, size = m.groups()
            status = int(status)
            size = int(size)
            status_codes[status] += 1
            ips[ip] += 1
            endpoint = url.split('?')[0]
            endpoints[endpoint] += 1
            decoded_url = unquote(url)
            nginx_entries.append({
                'ip': ip, 'ts': ts, 'method': method, 'url': decoded_url,
                'status': status, 'size': size
            })
            # Suspeito: payloads longos, erros, ou padrões estranhos
            if status in (400, 401, 403, 500) or len(url) > 200 or any(
                p in decoded_url.lower() for p in 
                ['union', 'select', 'sleep(', 'benchmark', "'", '"', '--', '/*', '*/', '0x', 'char(', 'exec(', 'xp_', 'information_schema']
            ):
                suspicious_urls.append({'ip': ip, 'url': decoded_url, 'status': status, 'ts': ts})

print(f"\n[Status codes]")
for code, cnt in sorted(status_codes.items()):
    print(f"  {code}: {cnt}")

print(f"\n[Top 15 IPs mais ativos]")
for ip, cnt in sorted(ips.items(), key=lambda x: -x[1])[:15]:
    print(f"  {ip}: {cnt} requests")

print(f"\n[Endpoints mais acessados]")
for ep, cnt in sorted(endpoints.items(), key=lambda x: -x[1])[:15]:
    print(f"  ({cnt:4d}x) {ep}")

print(f"\n[URLs suspeitas (primeiras 30)]")
if suspicious_urls:
    for s in suspicious_urls[:30]:
        print(f"  [{s['status']}] {s['ip']} | {s['ts']} | {s['url'][:200]}")
else:
    print("  Nenhuma encontrada")

# Check for very large or very small responses (potential exfil or errors)
print(f"\n[Respostas com tamanho incomum (>10000 bytes)]")
large = [e for e in nginx_entries if e['size'] > 10000]
for e in large[:15]:
    print(f"  size={e['size']} | [{e['status']}] {e['ip']} | {e['url'][:150]}")

print(f"\n[Respostas com tamanho 0]")
zero = [e for e in nginx_entries if e['size'] == 0]
print(f"  Total: {len(zero)}")
for e in zero[:10]:
    print(f"  [{e['status']}] {e['ip']} | {e['url'][:150]}")

# ─── SYSLOG ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("ANÁLISE: syslog(1).log")
print("=" * 80)

syslog_path = "syslog(1).log"
ssh_accepted = []
ssh_failed = []
sudo_cmds = []
ufw_blocks = []
suspicious_syslog = []

with open(syslog_path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if 'Accepted password' in line:
            ssh_accepted.append(line)
        elif 'Failed password' in line:
            ssh_failed.append(line)
        elif 'sudo' in line and 'COMMAND' in line:
            sudo_cmds.append(line)
        elif 'ufw-block' in line:
            ufw_blocks.append(line)
        # Anything unusual
        if any(p in line for p in ['wget', 'curl', 'nc ', 'netcat', 'bash', 'python', 'perl', 'ruby', '/tmp/', 'chmod', 'chown', 'passwd', 'shadow', 'crontab', 'base64', 'whoami', 'id ;']):
            suspicious_syslog.append(line)

print(f"\n[SSH - Logins bem-sucedidos ({len(ssh_accepted)})]")
for line in ssh_accepted:
    print(f"  {line}")

print(f"\n[SSH - Falhas de login ({len(ssh_failed)})]")
for line in ssh_failed:
    print(f"  {line}")

print(f"\n[Sudo executados ({len(sudo_cmds)})]")
# Group by command
cmd_users = defaultdict(list)
for line in sudo_cmds:
    m = re.search(r'sudo\[\d+\]:\s+(\S+)\s+:.*COMMAND=(.*)', line)
    if m:
        user = m.group(1)
        cmd = m.group(2).strip()
        cmd_users[cmd].append(user)

for cmd, users in cmd_users.items():
    print(f"  CMD: {cmd} | Users: {set(users)}")

print(f"\n[UFW blocks - External IPs]")
src_ips = []
for line in ufw_blocks:
    m = re.search(r'SRC=(\S+)', line)
    if m:
        src_ips.append(m.group(1))
src_counter = Counter(src_ips)
for ip, cnt in src_counter.most_common(10):
    print(f"  {ip}: {cnt}x blocked")

print(f"\n[Linhas suspeitas no syslog]")
if suspicious_syslog:
    for line in suspicious_syslog:
        print(f"  {line}")
else:
    print("  Nenhuma encontrada com padrões óbvios")

# ─── CORRELAÇÃO: SSH accepted + nginx  ────────────────────────────────────────
print("\n" + "=" * 80)
print("CORRELAÇÃO: IPs com SSH aceito vs IPs no nginx")
print("=" * 80)

accepted_ips = set()
for line in ssh_accepted:
    m = re.search(r'from (\S+) port', line)
    if m:
        accepted_ips.add(m.group(1))

print(f"IPs com SSH aceito: {accepted_ips}")
nginx_ips_set = set(ips.keys())
overlap = accepted_ips & nginx_ips_set
print(f"Desses, aparecem também no nginx: {overlap}")

# ─── EXTRA: procura por strings tipo flag  ───────────────────────────────────
print("\n" + "=" * 80)
print("BUSCA POR PADRÕES DE FLAG (HTB{...}, CTF{...}, flag{...}, hotmart{...})")
print("=" * 80)

flag_pattern = re.compile(r'(?:HTB|CTF|flag|hotmart|FLAG)\{[^}]+\}', re.IGNORECASE)

for fname in ['app.log', 'nginx.log', 'syslog(1).log']:
    try:
        with open(fname, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        found = flag_pattern.findall(content)
        if found:
            print(f"\n[{fname}] FLAGS ENCONTRADAS:")
            for f_ in found:
                print(f"  {f_}")
        else:
            print(f"[{fname}] Nenhuma flag no formato padrão encontrada")
    except Exception as e:
        print(f"[{fname}] Erro: {e}")

print("\n\nAnálise completa!")
