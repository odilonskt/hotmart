import sys

NUMERO = (
    "5536930239076226863114598038703976060203987202366164237308087881976976939527"
    "8983741141536331969388105972215831714468299008490305930870781826614019841134"
    "6725029072331171921302124285021484352463805853258269711390717568911161641776"
    "7364138889271573024395940025763104473294268841668238490399895639168328281162"
    "5710409283298674299631660175981919176461930128690625245251463987493536997500"
    "740816625713718257504715189278132579413273"
)

def test_elf(b, name):
    idx = b.find(b'\x7fELF')
    if idx != -1:
        print(f"[{name}] ELF encontrado no offset {idx}!")
        return True
    return False

# 1. Big Endian
b_be = int(NUMERO).to_bytes((int(NUMERO).bit_length() + 7) // 8, 'big')
test_elf(b_be, "Big Endian")

# 2. Little Endian
b_le = int(NUMERO).to_bytes((int(NUMERO).bit_length() + 7) // 8, 'little')
test_elf(b_le, "Little Endian")

# 3. QR Numeric Payload directly
bits = ''
for i in range(0, len(NUMERO), 3):
    chunk = NUMERO[i:i+3]
    if len(chunk) == 3: bits += format(int(chunk), '010b')
    elif len(chunk) == 2: bits += format(int(chunk), '07b')
    elif len(chunk) == 1: bits += format(int(chunk), '04b')

b_qr = []
for i in range(0, len(bits), 8):
    b_qr.append(int(bits[i:i+8].ljust(8, '0'), 2))
b_qr = bytes(b_qr)
test_elf(b_qr, "QR Payload")

# 4. QR bits offset search
import re
# \x7f E L F = 01111111 01000101 01001100 01000110
elf_bits = "01111111010001010100110001000110"
if elf_bits in bits:
    print(f"[QR Bits] ELF encontrado no offset {bits.find(elf_bits)} bits!")

# 5. Reverse numeric string
NUM_REV = NUMERO[::-1]
b_be_rev = int(NUM_REV).to_bytes((int(NUM_REV).bit_length() + 7) // 8, 'big')
test_elf(b_be_rev, "Reversed Big Endian")

print("Busca completa finalizada.")
