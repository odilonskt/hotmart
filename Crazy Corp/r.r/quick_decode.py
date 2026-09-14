#!/usr/bin/env python3
"""
Script de decodificação rápida - Ferramentas individuais
Cada função pode ser usada independentemente.
"""

import base64
import binascii


def hex_to_ascii(hex_string):
    """Converte string hexadecimal para ASCII."""
    hex_clean = hex_string.replace(":", "").replace(" ", "").replace("\n", "")
    return bytes.fromhex(hex_clean).decode('ascii', errors='replace')


def xor_decrypt(data_hex, key=0x42):
    """Descriptografa dados hex com XOR."""
    data = bytes.fromhex(data_hex.replace(" ", "").replace(":", ""))
    return bytes([b ^ key for b in data]).decode('ascii', errors='replace')


def base64_decode(b64_string):
    """Decodifica Base64 com auto-padding."""
    padding = len(b64_string) % 4
    if padding:
        b64_string += "=" * (4 - padding)
    return base64.b64decode(b64_string).decode('utf-8', errors='replace')


def rot13(text):
    """Decodifica ROT13."""
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)


def caesar_decrypt(text, shift):
    """Decodifica cifra de César com deslocamento dado."""
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)


def brute_xor(data_hex, max_key=255):
    """Tenta todas as chaves XOR e mostra resultados legíveis."""
    data = bytes.fromhex(data_hex.replace(" ", ""))
    results = []
    for key in range(max_key + 1):
        decrypted = bytes([b ^ key for b in data])
        try:
            text = decrypted.decode('ascii')
            if text.isprintable():
                results.append((key, text))
        except:
            pass
    return results


# ============================================================
# EXECUÇÃO DIRETA - Decodifica tudo do desafio Crazy Corp
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print(" CRAZY CORP - QUICK DECODE TOOLKIT")
    print("=" * 60)
    
    # 1. Hex do Modulus RSA
    print("\n[1] HEX → ASCII (Modulus RSA)")
    modulus_hex = ("64 6f 6e 6f 74 65 63 68 6f 7b 74 48 33 "
                   "5f 6e 33 54 77 30 72 4b 5f 30 66 5f 74 48 33 "
                   "5f 46 75 54 75 72 33 5f 34 6c 72 33 34 44 79 "
                   "5f 33 78 31 35 74 35 5f 38 37 34 32 31 35 35")
    print(f"    Resultado: {hex_to_ascii(modulus_hex)}")
    
    # 2. Base64 do corpo PEM
    print("\n[2] BASE64 → Texto (Corpo PEM)")
    b64 = ("ZG9ub3RlY2hve3RIM19uM1R3MHJLXzBmX3RIM19GdVR1cjNfNGxyMzREeV8zeDE1"
           "dDVfODc0MjE1NX0KCkhpbnQ6IFRoaXMgY2VydGlmaWNhdGUgY29udGFpbnMgdGhl"
           "IGZsYWcgaW4gbXVsdGlwbGUgcGxhY2VzLiBDaGVjayB0aGUgbW9kdWx1cyBhbmQg"
           "dGhlIHNlcmlhbCBudW1iZXIuCgpTZXJpYWwgTnVtYmVyIEhpbnQ6IDg3NDIxNTUw")
    print(f"    Resultado: {base64_decode(b64)}")
    
    # 3. Authority Key ID
    print("\n[3] AUTHORITY KEY ID → Grupo Atacante")
    auth_key = "SH:AD:OW:SY:ND:IC:AT:E0"
    parts = auth_key.replace(":", "")
    print(f"    Resultado: SHADOW SYNDICATE (de '{auth_key}')")
    
    # 4. Subject Key Identifier
    print("\n[4] SUBJECT KEY ID → Padrões")
    ski = "87:42:15:5D:EA:DB:EE:F0:CA:FE:BA:BE:DE:AD:BE:EF"
    print(f"    SKI: {ski}")
    print(f"    Padrões: 8742155 + DEADBEEF + CAFEBABE + DEADBEEF")
    
    print("\n" + "=" * 60)
    print(f" FLAG: donotecho{{tH3_n3Tw0rK_0f_tH3_FuTur3_4lr34Dy_3x15t5_8742155}}")
    print("=" * 60)
