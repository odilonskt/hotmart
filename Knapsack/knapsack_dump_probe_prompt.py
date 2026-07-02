import socket
import json
import re

HOST = "98.94.69.132"
PORT = 32442


def recv_some(s, timeout=10.0, max_bytes=10_000_000):
    s.settimeout(timeout)
    buf = bytearray()
    while True:
        try:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
            if len(buf) >= max_bytes:
                break
        except TimeoutError:
            break
    return bytes(buf)


def extract_json_obj(txt: str):
    # pega a primeira ocorrência de JSON
    m = re.search(r"\{.*\}", txt, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except Exception:
        return None


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[+] Conectando em {HOST}:{PORT}...")
        s.connect((HOST, PORT))
        print("[+] Conectado!")

        buf = recv_some(s, timeout=8.0)
        print(f"\n[+] Total bytes recebidos: {len(buf)}")

        # tenta decodificar e localizar a instrução
        txt = buf.decode(errors="ignore")
        print("\n=== RAW TEXT (parcial) ===\n")
        print(txt)

        # tenta encontrar as palavras-chave
        keys = [
            "monta", "matriz", "envie", "respon", "resposta", "indice", "índice", "até", "100", "forma", "separ",
            "Invalid", "Wrong answer", "answer"
        ]
        for k in keys:
            if re.search(re.escape(k), txt, re.IGNORECASE):
                print(f"\n[+] Encontrado keyword: {k}")

        # se houver JSON, mostra quantidade de campos e um resumo
        data = extract_json_obj(txt)
        if data:
            print("\n[+] JSON detectado. Chaves:", list(data.keys()))
            if "capacity" in data:
                print("    capacity=", data.get("capacity"))
            if "values" in data:
                print("    n_values=", len(data.get("values", [])))


if __name__ == "__main__":
    main()

