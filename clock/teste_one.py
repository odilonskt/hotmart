from pwn import *

conn = remote('98.94.69.132', 32440)

# Recebe o banner
banner = conn.recvline()
print("Banner:", banner)

# Agora recebe TODO o resto dos dados (ou linha por linha)
dados = conn.recvall()
print("Dados recebidos:")
print(dados)          # em bytes
print(dados.decode()) # tenta decodificar como texto