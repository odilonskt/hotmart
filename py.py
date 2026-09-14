import requests
import time

# Configurações do alvo do CTF
BASE_URL = "http://32.193.244.76:32452"

# -------------------------------------------------------------------------
# Implementação exata do algoritmo cipher.js em Python
# -------------------------------------------------------------------------
_p = [0x9e, 0x37, 0x79, 0xb1]

def _r(v, n):
    n &= 7
    v &= 255
    return ((v << n) | (v >> (8 - n))) & 255

def _s(x):
    return (((x * 0x4d) & 255) ^ 0x35) & 255

def _g(shard, k):
    a = (0x1b ^ ((k * 0x5f) & 255)) & 255
    for i in range(len(shard)):
        b = shard[i] & 255
        a = _r(a ^ b, (i + k + 1) & 7)
        a = (a + _p[(b + i) & 3]) & 255
        a = _s(a)
    return a

# -------------------------------------------------------------------------
# Fluxo de Automação do Desafio
# -------------------------------------------------------------------------
def solve_challenge():
    # Usamos um Session para manter cookies ou conexões persistentes se necessário
    session = requests.Session()
    
    print("[*] Buscando novo desafio em /challenge...")
    try:
        # 1. Pega o desafio atual do servidor
        response = session.get(f"{BASE_URL}/challenge")
        if response.status_code != 200:
            print(f"[-] Erro ao acessar o desafio: Status {response.status_code}")
            return
            
        data = response.json()
        fragments = data.get("fragments")
        challenge_info = data.get("challenge", {})
        
        if not fragments:
            print("[-] Não foi possível extrair os fragmentos da resposta.")
            return
            
        print(f"[+] Fragmentos recebidos: {fragments}")
        
        # 2. Calcula os bytes correspondentes para cada um dos 4 canais
        echo_bytes = []
        for k in range(4):
            byte_val = _g(fragments, k)
            # Converte para string hexadecimal com 2 caracteres
            echo_bytes.append(f"{byte_val:02x}")
            
        print(f"[+] Bytes de eco calculados: {echo_bytes}")
        
        # 3. Monta o payload para submissão contendo os dados da verificação
        # O servidor espera o formato enviado na requisição POST /verify
        payload = {
            "challenge": {
                "exp": challenge_info.get("exp"),
                "nonce": challenge_info.get("nonce"),
                "sig": challenge_info.get("sig")
            },
            "fragments": fragments,
            "npcTrace": [42, 42, 42],  # Baseado nos traces do log da rede capturado
            "timeline": ["micro", "frame", "macro", "worker"], # Ordem da ressonância validada
            "persistMark": 195,
            "echoBytes": echo_bytes
        }
        
        print("[*] Enviando solução para /verify...")
        # 4. Envia a resposta calculada
        verify_res = session.post(f"{BASE_URL}/verify", json=payload)
        
        print(f"[*] Resposta do Servidor (Status {verify_res.status_code}):")
        print("==================================================")
        print(verify_res.text)
        print("==================================================")
        
    except Exception as e:
        print(f"[-] Ocorreu um erro durante a execução: {e}")

if __name__ == "__main__":
    solve_challenge()