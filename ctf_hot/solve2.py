import base64
import zlib

NUMERO = (
    "5536930239076226863114598038703976060203987202366164237308087881976976939527"
    "8983741141536331969388105972215831714468299008490305930870781826614019841134"
    "6725029072331171921302124285021484352463805853258269711390717568911161641776"
    "7364138889271573024395940025763104473294268841668238490399895639168328281162"
    "5710409283298674299631660175981919176461930128690625245251463987493536997500"
    "740816625713718257504715189278132579413273"
)

# Tentativa 1: int puro (big-endian)
try:
    num_bytes = (int(NUMERO).bit_length() + 7) // 8
    b_be = int(NUMERO).to_bytes(num_bytes, 'big')
    print("Int puro (BE) começa com:", b_be[:10])
except Exception as e: pass

# Tentativa 2: int puro (little-endian)
try:
    b_le = int(NUMERO).to_bytes(num_bytes, 'little')
    print("Int puro (LE) começa com:", b_le[:10])
except Exception as e: pass

# Tentativa 3: payload numérico do QR (grupos de 10 bits)
try:
    bits = ''
    for i in range(0, len(NUMERO), 3):
        chunk = NUMERO[i:i+3]
        if len(chunk) == 3: bits += format(int(chunk), '010b')
        elif len(chunk) == 2: bits += format(int(chunk), '07b')
        elif len(chunk) == 1: bits += format(int(chunk), '04b')
    bytes_list = []
    for i in range(0, len(bits), 8):
        byte_str = bits[i:i+8]
        if len(byte_str) == 8: bytes_list.append(int(byte_str, 2))
        else: bytes_list.append(int(byte_str.ljust(8, '0'), 2))
    b_qr = bytes(bytes_list)
    print("QR Payload 10-bit começa com:", b_qr[:10])
except Exception as e: pass

# Tentativa 4: O ELF foi lido byte a byte e convertido em string decimal com 3 dígitos (zfill)?
# Ex: 127 069 076 070... Mas não é o caso pois começa com 553.

# Tentativa 5: Base85
# Não aplicável, é puramente numérico.

print("---")
print("Se você conseguir ver algum padrão, copie a saída e mande aqui!")
