from pwn import *

conn = remote('98.94.69.132', 32441)

# Vamos ler tudo o que o servidor enviar até ele pedir entrada
# ou até um timeout de 5 segundos após a última linha.
data = b''
while True:
    try:
        # Tenta ler uma linha com timeout de 2 segundos
        line = conn.recvline(timeout=2)
        if not line:
            break
        data += line
        print(line.decode(), end='')  # Mostra em tempo real
        # Se a linha contiver "Digite" ou ":" ou ">", provavelmente é o prompt
        if b'Digite' in line or b':' in line or b'>' in line:
            # Dá um tempinho para ver se vem mais dados
            time.sleep(0.5)
            # Tenta ler mais uma linha
            extra = conn.recvline(timeout=1)
            if extra:
                data += extra
                print(extra.decode(), end='')
            break
    except Exception as e:
        print(f"Erro: {e}")
        break

conn.close()
print("\n[Fim da captura]")