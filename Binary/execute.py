import socket
import re
import ast

HOST = "98.94.69.132"
PORT = 32443

def guaranteed_elements(arr):
    n = len(arr)
    if not n:
        return []

    left_max = [float('-inf')] * n
    right_min = [float('inf')] * n

    for i in range(1, n):
        left_max[i] = max(left_max[i-1], arr[i-1])

    for i in range(n-2, -1, -1):
        right_min[i] = min(right_min[i+1], arr[i+1])

    return sorted(
        arr[i]
        for i in range(n)
        if left_max[i] < arr[i] < right_min[i]
    )

s = socket.create_connection((HOST, PORT))

buffer = ""

while True:
    data = s.recv(4096)
    if not data:
        break

    text = data.decode(errors="replace")
    print(text, end="")

    buffer += text

    # procura algo como [1,2,3,4]
    arrays = re.findall(r'\[[^\]]*\]', buffer)

    for a in arrays:
        try:
            arr = ast.literal_eval(a)

            if isinstance(arr, list):
                ans = guaranteed_elements(arr)
                payload = str(ans) + "\n"

                print(f"\n[+] Enviando: {payload.strip()}")
                s.sendall(payload.encode())

                buffer = ""
        except:
            pass