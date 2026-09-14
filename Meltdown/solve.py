import base64

s = "GV2DG3JVL42AC2"
# pad to multiple of 8
s += "=" * ((8 - len(s) % 8) % 8)
try:
    print(base64.b32decode(s))
except Exception as e:
    print("Error decoding base32:", e)
