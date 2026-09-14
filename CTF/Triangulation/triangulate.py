#!/usr/bin/env python3
"""
TRIANGULAÇÃO: Correlação cruzada dos 3 logs para encontrar a mentira
- app.log     (JSON)
- nginx.log   (nginx combined)
- syslog.log  (Linux syslog)

A "testemunha que mente pela metade" é o log com eventos inconsistentes
em relação aos outros dois. A triangulação desses 3 revela o crime.
"""
import re
import json
from datetime import datetime, timezone, timedelta
from collections import defaultdict

# ─── Parsers de cada "língua" ────────────────────────────────────────────────

def parse_app_log(path):
    """JSON structured logs (app.log)"""
    events = []
    buf = ""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.rstrip()
            if line.startswith('{'):
                buf = line
            elif buf:
                buf += line
            try:
                obj = json.loads(buf)
                ts_str = obj.get('timestamp', '')
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                events.append({
                    'source': 'app',
                    'ts': ts,
                    'ts_str': ts_str,
                    'level': obj.get('level', ''),
                    'service': obj.get('service', ''),
                    'message': obj.get('message', ''),
                    'raw': obj,
                    'req_ref': None
                })
                # Extract req_ref if error
                st = obj.get('stack_trace', '')
                m = re.search(r'req_ref: (0x[0-9a-fA-F]+)', st)
                if m:
                    events[-1]['req_ref'] = m.group(1)
                buf = ""
            except:
                pass
    return events

def parse_nginx_log(path):
    """nginx combined log format"""
    events = []
    pattern = re.compile(
        r'^(\S+) - - \[(\d{2}/\w+/\d{4}):(\d{2}:\d{2}:\d{2}) ([+-]\d{4})\] '
        r'"(\S+) (\S+) HTTP/[^"]+" (\d{3}) (\d+)(?: "([^"]*)" "([^"]*)")?'
    )
    months = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
              'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = pattern.match(line.strip())
            if not m:
                continue
            ip, date, time, tz, method, url, status, size = m.groups()[:8]
            d, mon, y = date.split('/')
            dt_str = f"{y}-{months[mon]:02d}-{int(d):02d}T{time}+00:00"
            ts = datetime.fromisoformat(dt_str)
            events.append({
                'source': 'nginx',
                'ts': ts,
                'ts_str': dt_str,
                'ip': ip,
                'method': method,
                'url': url,
                'status': int(status),
                'size': int(size),
            })
    return events

def parse_syslog(path):
    """Linux syslog format"""
    events = []
    pattern = re.compile(r'^(\S+) auth-server (\S+): (.+)$')
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            m = pattern.match(line)
            if not m:
                continue
            ts_str, process, message = m.groups()
            try:
                ts = datetime.fromisoformat(ts_str)
            except:
                continue
            events.append({
                'source': 'syslog',
                'ts': ts,
                'ts_str': ts_str,
                'process': process,
                'message': message,
                'raw': line
            })
    return events

# ─── Carregar todos ──────────────────────────────────────────────────────────
print("Carregando logs...")
app_events = parse_app_log('app.log')
nginx_events = parse_nginx_log('nginx.log')
syslog_events = parse_syslog('syslog(1).log')

print(f"  app.log:  {len(app_events)} eventos")
print(f"  nginx:    {len(nginx_events)} eventos")
print(f"  syslog:   {len(syslog_events)} eventos")

SUSPICIOUS_IPS = {'198.51.100.10', '198.51.100.20', '198.51.100.30'}

# ─── Análise dos IPs suspeitos no nginx ─────────────────────────────────────
print("\n" + "="*80)
print("OS TRÊS ATACANTES (198.51.100.x) — ANÁLISE COMPLETA")
print("="*80)

for ip in sorted(SUSPICIOUS_IPS):
    ip_events = [e for e in nginx_events if e['ip'] == ip]
    print(f"\n{'─'*60}")
    print(f"[{ip}] — {len(ip_events)} requisições")
    
    # Status codes
    from collections import Counter
    sc = Counter(e['status'] for e in ip_events)
    print(f"  Status: {dict(sc)}")
    
    # Endpoints únicos e contagem
    ep = Counter(e['url'].split('?')[0] for e in ip_events)
    print(f"  Top 10 endpoints:")
    for endpoint, cnt in ep.most_common(10):
        print(f"    {cnt:3d}x  {endpoint}")
    
    # Requisições com status != 200
    non200 = [e for e in ip_events if e['status'] != 200]
    print(f"\n  Respostas não-200 ({len(non200)}):")
    for e in non200[:15]:
        print(f"    [{e['status']}] {e['ts_str']} | {e['method']} {e['url'][:80]}")
    
    # Primeira e última requisição
    print(f"\n  Janela temporal: {ip_events[0]['ts_str']} → {ip_events[-1]['ts_str']}")

# ─── CORRELAÇÃO TEMPORAL: O mesmo minuto nos 3 logs ─────────────────────────
print("\n" + "="*80)
print("CORRELAÇÃO TEMPORAL: Eventos simultâneos nos 3 logs")
print("="*80)

WINDOW = 60  # segundos de janela

# Indexar por minuto
def bucket_minute(events):
    d = defaultdict(list)
    for e in events:
        key = e['ts'].replace(second=0, microsecond=0)
        d[key].append(e)
    return d

app_by_min = bucket_minute(app_events)
nginx_by_min = bucket_minute(nginx_events)
syslog_by_min = bucket_minute(syslog_events)

# Janelas com atividade nos 3 ao mesmo tempo
all_minutes = set(app_by_min) | set(nginx_by_min) | set(syslog_by_min)
triple_hits = []
for minute in sorted(all_minutes):
    has_app = minute in app_by_min
    has_nginx = minute in nginx_by_min
    has_syslog = minute in syslog_by_min
    if has_app and has_nginx and has_syslog:
        # Checar se tem IP suspeito no nginx nesse minuto
        suspicious_in_minute = [e for e in nginx_by_min[minute] if e['ip'] in SUSPICIOUS_IPS]
        if suspicious_in_minute:
            triple_hits.append((minute, nginx_by_min[minute], app_by_min[minute], syslog_by_min[minute]))

print(f"\nMinutos com atividade simultânea nos 3 logs + IP suspeito: {len(triple_hits)}")
for minute, nginx_e, app_e, sys_e in triple_hits[:10]:
    print(f"\n  ⏱  {minute}")
    print(f"    [nginx ] {[e['ip']+' '+e['url'][:40] for e in nginx_e if e['ip'] in SUSPICIOUS_IPS][:3]}")
    print(f"    [app   ] {[(e['level'], e['message'][:40]) for e in app_e[:2]]}")
    print(f"    [syslog] {[e['message'][:60] for e in sys_e[:2]]}")

# ─── A "TESTEMUNHA QUE MENTE": inconsistências ─────────────────────────────
print("\n" + "="*80)
print("A TESTEMUNHA QUE MENTE: Buscando inconsistências entre logs")
print("="*80)

# Hipótese 1: nginx reporta 200 mas app.log reporta ERROR no mesmo minuto
print("\n[Hipótese 1] nginx=200 + app=ERROR no mesmo minuto")
for minute in sorted(all_minutes):
    if minute not in nginx_by_min or minute not in app_by_min:
        continue
    nginx_200 = [e for e in nginx_by_min[minute] if e['status'] == 200 and e['ip'] in SUSPICIOUS_IPS]
    app_errors = [e for e in app_by_min[minute] if e['level'] == 'ERROR']
    if nginx_200 and app_errors:
        for n in nginx_200[:2]:
            for a in app_errors[:2]:
                print(f"  {minute} | nginx: [{n['status']}] {n['ip']} {n['url'][:50]}")
                print(f"           | app  : [{a['level']}] {a['message'][:50]}")
                if a.get('req_ref'):
                    print(f"           | ref  : {a['req_ref']}")

# Hipótese 2: SSH login bem-sucedido mas origem não bate com nginx
print("\n[Hipótese 2] SSH aceito de IP que não aparece no nginx")
ssh_accepted_ips = set()
for e in syslog_events:
    m = re.search(r'Accepted password.*from (\S+) port', e['message'])
    if m:
        ssh_accepted_ips.add(m.group(1))

nginx_ips = set(e['ip'] for e in nginx_events)
ssh_not_in_nginx = ssh_accepted_ips - nginx_ips
print(f"  SSH aceito mas IP ausente no nginx: {ssh_not_in_nginx}")

# Hipótese 3: Verificar se timestamps do app.log são consistentes
# (ex: eventos fora de ordem cronológica)
print("\n[Hipótese 3] Verificar consistência temporal do app.log")
prev_ts = None
inconsistencies_app = []
for e in app_events:
    if prev_ts and e['ts'] < prev_ts - timedelta(seconds=5):
        inconsistencies_app.append((prev_ts, e['ts'], e))
    prev_ts = e['ts']
print(f"  Eventos fora de ordem no app.log: {len(inconsistencies_app)}")
for prev, cur, e in inconsistencies_app[:5]:
    print(f"    Retrocesso: {prev} → {cur} | {e['message'][:50]}")

# ─── FOCO: O que os 3 IPs suspeitos têm em COMUM ─────────────────────────
print("\n" + "="*80)
print("TRIANGULAÇÃO: O que os 3 IPs suspeitos têm em comum?")
print("="*80)

ip_endpoints = {}
for ip in SUSPICIOUS_IPS:
    ip_events_list = [e for e in nginx_events if e['ip'] == ip]
    ip_endpoints[ip] = set(e['url'].split('?')[0] for e in ip_events_list)

# Interseção: endpoints visitados pelos 3 ao mesmo tempo
common_all = ip_endpoints['198.51.100.10'] & ip_endpoints['198.51.100.20'] & ip_endpoints['198.51.100.30']
print(f"\nEndpoints visitados pelos 3 IPs: {len(common_all)}")
for ep in sorted(common_all):
    print(f"  {ep}")

# Endpoints exclusivos de cada IP
for ip in sorted(SUSPICIOUS_IPS):
    others = SUSPICIOUS_IPS - {ip}
    other_eps = set()
    for other in others:
        other_eps |= ip_endpoints[other]
    exclusive = ip_endpoints[ip] - other_eps
    print(f"\n  [{ip}] endpoints exclusivos: {sorted(exclusive)[:10]}")

# ─── Req_refs: Tentar decodificação como sequência de chars via XOR ou offset
print("\n" + "="*80)
print("REQ_REFS: Todas as tentativas de decodificação")
print("="*80)

with open('app.log', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

refs = re.findall(r'req_ref: (0x[0-9a-fA-F]+)', content)
vals = [int(r, 16) for r in refs]

# Tentar: valor como número, módulo 95 + 32 = printable ASCII
mod95 = [v % 95 + 32 for v in vals]
print(f"\nv % 95 + 32 (printable):")
print('  ' + ''.join(chr(c) for c in mod95[:100]))

# Tentar: soma dos bytes
sum_bytes = [sum(v.to_bytes(4, 'big')) % 95 + 32 for v in vals]
print(f"\nsum_bytes % 95 + 32:")
print('  ' + ''.join(chr(c) for c in sum_bytes[:100]))

# Tentar: cada nibble como índice
nibbles = []
for v in vals:
    for shift in [20, 16, 12, 8, 4, 0]:
        nibbles.append((v >> shift) & 0xF)

print(f"\nNibbles como índice A-P:")
nibble_chars = [chr(ord('A') + n) for n in nibbles[:200]]
print('  ' + ''.join(nibble_chars))

# Tentar pares de bytes como coordenadas de 16 bits
print(f"\nPrimeiros 10 refs como pares de shorts (lat/lon * 100):")
for i, v in enumerate(vals[:10]):
    high = (v >> 12) & 0xFFF  # 12 bits altos
    low = v & 0xFFF            # 12 bits baixos
    print(f"  {refs[i]} | high={high} ({high/10:.1f}°) low={low} ({low/10:.1f}°)")

# Tentar: apenas os bits 8-15 (byte 2)
byte2 = [(v >> 8) & 0xFF for v in vals]
print(f"\nByte 2 (v>>8 & 0xFF):")
print('  ' + ''.join(chr(b) if 32 <= b <= 126 else '.' for b in byte2[:100]))

# ─── BUSCA: Flag em URLs do nginx (params, headers, etc) ──────────────────
print("\n" + "="*80)
print("BUSCA: Parâmetros/Queries dos IPs suspeitos")
print("="*80)
for ip in sorted(SUSPICIOUS_IPS):
    print(f"\n[{ip}] URLs com query string:")
    with_qs = [e for e in nginx_events if e['ip'] == ip and '?' in e['url']]
    for e in with_qs[:20]:
        print(f"  [{e['status']}] {e['url']}")
