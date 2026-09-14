import qrcode
from PIL import Image
from pyzbar.pyzbar import decode
import os

# A string gigante (copie exatamente do seu writeup)
NUMERO = (
    "5536930239076226863114598038703976060203987202366164237308087881976976939527"
    "8983741141536331969388105972215831714468299008490305930870781826614019841134"
    "6725029072331171921302124285021484352463805853258269711390717568911161641776"
    "7364138889271573024395940025763104473294268841668238490399895639168328281162"
    "5710409283298674299631660175981919176461930128690625245251463987493536997500"
    "740816625713718257504715189278132579413273"
)

# 1. Gerar o QR Code (modo numérico automático)
qr = qrcode.QRCode(
    version=None,  # ajusta automaticamente
    error_correction=qrcode.constants.ERROR_CORRECT_M,
    box_size=10,
    border=4,
)
qr.add_data(NUMERO)
qr.make(fit=True)
img = qr.make_image(fill_color="black", back_color="white")
img.save("qrcode.png")
print("QR Code gerado: qrcode.png")

# 2. Decodificar o QR Code para obter os dados originais (string numérica)
# Isso serve para verificar se a codificação está correta.
decoded = decode(Image.open("qrcode.png"))
if not decoded:
    raise RuntimeError("Falha ao decodificar o QR Code.")

dados_decodificados = decoded[0].data.decode()
print(f"Dados decodificados (primeiros 50 caracteres): {dados_decodificados[:50]}...")
assert dados_decodificados == NUMERO, "A decodificação não corresponde ao número original!"

# 3. Vamos imprimir o valor hexadecimal e ver se tem algo escondido
numero_int = int(NUMERO)
hex_str = hex(numero_int)
print("Tamanho do hex:", len(hex_str))
print("Hexadecimal (primeiros 50 chars):", hex_str[:50])

# Fim do teste
