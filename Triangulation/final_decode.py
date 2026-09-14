#!/usr/bin/env python3
"""
FINAL: Extrai req_refs EXCLUSIVOS da janela do ataque SQLi (14:00-14:03)
e tenta decodificar credenciais exfiltradas.
"""
import re
import json
from datetime import datetime

# Janela do ataque sqlmap
ATTACK_START = datetime.fromisoformat("2026-07-05T14:00:00+00:00")
ATTACK_END   = datetime.fromisoformat("2026-07-05T14:03:00+00:00")

# ─── Coleta req_refs DURANTE e FORA do ataque ────────────────────────────────
attack_refs = []
normal_refs = []
attack_errors = []

buf = ""
with open("app.log", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.rstrip()
        if line.startswith("{"):
            buf = line
        elif buf:
            buf += line
        try:
            obj = json.loads(buf)
            ts = datetime.fromisoformat(obj["timestamp"].replace("Z", "+00:00"))
            st = obj.get("stack_trace", "")
            m = re.search(r"req_ref: (0x[0-9a-fA-F]+)", st)
            if m:
                ref = m.group(1)
                val = int(ref, 16)
                if ATTACK_START <= ts <= ATTACK_END:
                    attack_refs.append((ts, ref, val, obj))
                    attack_errors.append(obj)
                else:
                    normal_refs.append(val)
            buf = ""
        except:
            pass

print("=" * 70)
print("REQ_REFS DURANTE O ATAQUE SQLI (14:00-14:03)")
print("=" * 70)
print(f"Total de refs NO ataque:  {len(attack_refs)}")
print(f"Total de refs fora ataque: {len(normal_refs)}")

# Refs únicos do ataque (não aparecem no resto do log)
normal_set = set(normal_refs)
exclusive_attack = [(ts, r, v, o) for ts, r, v, o in attack_refs if v not in normal_set]
print(f"Refs EXCLUSIVOS do ataque: {len(exclusive_attack)}")

print("\n--- Todos os refs do período do ataque ---")
seen = set()
unique_attack = []
for ts, r, v, o in attack_refs:
    if r not in seen:
        seen.add(r)
        unique_attack.append((ts, r, v))
        
for ts, r, v in unique_attack:
    b = v.to_bytes(4, "big")
    ascii3 = "".join(chr(x) if 32 <= x <= 126 else f"\\x{x:02x}" for x in b)
    print(f"  {ts.strftime('%H:%M:%S')} | {r:12s} | dec={v:10d} | bytes={b.hex()} | ascii='{ascii3}'")

# ─── Decode tentativas focadas ────────────────────────────────────────────────
print("\n" + "=" * 70)
print("DECODIFICANDO OS REFS DO ATAQUE")
print("=" * 70)

vals_attack = [v for _, _, v in unique_attack]
refs_attack = [r for _, r, _ in unique_attack]

# Os 3 refs do ataque — tentar XOR entre eles
if len(vals_attack) >= 2:
    print(f"\n[XOR entre os refs do ataque]")
    for i in range(len(vals_attack)):
        for j in range(i+1, len(vals_attack)):
            x = vals_attack[i] ^ vals_attack[j]
            b = x.to_bytes(4, "big")
            s = "".join(chr(c) if 32 <= c <= 126 else "." for c in b)
            print(f"  {refs_attack[i]} XOR {refs_attack[j]} = 0x{x:08x} -> '{s}'")

# Tentar interpretar como dois inteiros de 14 bits = charset
print(f"\n[Cada ref como 14+14 bits]")
for ts, r, v in unique_attack:
    hi14 = (v >> 14) & 0x3FFF
    lo14 = v & 0x3FFF
    print(f"  {r}: hi14={hi14} lo14={lo14} | {chr(hi14 % 95 + 32)}{chr(lo14 % 95 + 32)}")

# Tentar: valor inteiro como encoded string (base-26, base-36, etc)
print(f"\n[Base-36 decoding]")
import string
ALPHA = string.digits + string.ascii_lowercase
for ts, r, v in unique_attack:
    result = ""
    n = v
    while n:
        result = ALPHA[n % 36] + result
        n //= 36
    print(f"  {r} -> base36: {result}")

# Tentar: os bytes 1-3 (ignorar byte mais alto) como texto
print(f"\n[Bytes 1-3 de cada ref (ignorar byte 0)]")
text_b13 = ""
for _, _, v in unique_attack:
    b = v.to_bytes(4, "big")
    for x in b[1:]:
        text_b13 += chr(x) if 32 <= x <= 126 else f"[{x:02x}]"
print(f"  {''.join(text_b13)}")

# Exibir os payloads SQLi encontrados com 200
print("\n" + "=" * 70)
print("PAYLOADS SQLi com resposta 200 (UNION SELECT encontrado)")
print("=" * 70)

from urllib.parse import unquote
nginx_pat = re.compile(
    r'^(\S+) - - \[([^\]]+)\] "(\S+) (\S+) HTTP/[^"]+" (\d{3}) (\d+)'
)
sqli_success = []
with open("nginx.log", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        m = nginx_pat.match(line.strip())
        if not m: continue
        ip, ts, method, url, status, size = m.groups()
        if ip == "198.51.100.30" and int(status) == 200:
            decoded = unquote(url)
            if "UNION" in decoded.upper() or "SELECT" in decoded.upper():
                sqli_success.append(decoded)

unique_payloads = list(dict.fromkeys(sqli_success))
print(f"\nPayloads UNION/SELECT únicos com 200:")
for p in unique_payloads:
    print(f"  {p}")

# Verificar o syslog no momento do ataque
print("\n" + "=" * 70)
print("SYSLOG durante o ataque (14:00-14:03)")
print("=" * 70)
with open("syslog(1).log", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if "14:0" in line[:30] and "2026-07-05" in line:
            print(f"  {line}")

# ─── CONCLUSÃO ────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("CONCLUSÃO FORENSE — TRIANGULAÇÃO")
print("=" * 70)
print("""
CRIME   : SQL Injection (Union-based + Time-based Blind)
ALVO    : /products/view?id= (aplicação vulnerável)
ATACANTE: 198.51.100.30 (sqlmap/1.7.2)
JANELA  : 2026-07-05 14:00:00 → 14:02:53 UTC (173 segundos)

TESTEMUNHAS:
  [1] nginx.log    → 200 para 750 payloads SQLi    (A QUE MENTE)
  [2] app.log      → ERROR no mesmo instante        (diz a verdade)
  [3] syslog.log   → silêncio às 14:00-14:03       (diz a verdade)

A MENTIRA: nginx.log reporta HTTP 200 para SLEEP(5) requests que
  levariam 3750+ segundos, mas toda a janela foi 173s. Impossível.
  Contradiz app.log que mostra ERROR no mesmo minuto.

DADO EXFILTRADO (payload UNION SELECT com 200):
  /products/view?id=1 UNION SELECT null,username,password FROM users
  → Tentativa de extração de credenciais da tabela `users`

DADOS OCULTOS: req_refs no app.log durante 14:01-14:02 codificam
  informação adicional sobre o que foi acessado.
""")

# ─── Tentar todas as decodificações possíveis dos refs do ataque ─────────────
print("DECODIFICAÇÕES ALTERNATIVAS DOS REFS DO ATAQUE:")
for ts, r, v in unique_attack:
    print(f"\n  [{r}] = {v}")
    # Como 3.5 bytes (28 bits) dividido em 4 chars de 7 bits
    chars_7bit = ""
    for shift in [21, 14, 7, 0]:
        c = (v >> shift) & 0x7F
        chars_7bit += chr(c) if 32 <= c <= 126 else f"[{c}]"
    print(f"    4x 7-bit chars: {chars_7bit}")
    # Como sequência de 3 chars de ~9 bits mapeados para ASCII
    c1 = (v >> 18) & 0x3FF
    c2 = (v >> 9) & 0x1FF
    c3 = v & 0x1FF
    print(f"    3 grupos: {c1}|{c2}|{c3}")
    # mod printable
    print(f"    mod95: {chr(v%95+32)}")
    print(f"    v//256 mod95: {chr((v//256)%95+32)}")
    print(f"    v//65536 mod95: {chr((v//65536)%95+32)}")
