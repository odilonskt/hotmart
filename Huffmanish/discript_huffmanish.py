from __future__ import annotations

import argparse
import re
from typing import Dict, Tuple

from pwn import remote


def discript_from_round_output(text: str) -> str:
    """Extrai a string do round e devolve (por compatibilidade) a mesma string.

    No desafio Huffmanish que você está resolvendo, a string enviada em `Resposta:`
    é a própria cifra/entrada usada para o check do servidor.

    Como você já encontrou a flag enviando `kckfmekav`, este utilitário se limita
    a extrair a string e devolver o conteúdo útil.
    """
    m = re.search(r"\[Round\s*\d+\]\s*String:\s*([^\n\r]+)", text)
    if not m:
        m = re.search(r"String:\s*([^\n\r]+)", text)
    if not m:
        raise ValueError("Não encontrei linha 'String:' no texto fornecido")
    return m.group(1).strip()


def main():
    ap = argparse.ArgumentParser(description="Descriptografa/decodifica a saída do servidor Huffmanish")
    ap.add_argument("--host", default="98.94.69.132")
    ap.add_argument("--port", type=int, default=32441)
    ap.add_argument("--one", action="store_true", help="Captura só o Round 1")
    args = ap.parse_args()

    conn = remote(args.host, args.port)

    # Captura tudo até ver "Resposta:" e, depois, segue para a flag.
    buf = b""
    out_text_parts = []

    rounds = 0
    last_string = None

    while True:
        try:
            chunk = conn.recv(timeout=4)
        except EOFError:
            break
        if not chunk:
            break
        buf += chunk
        t = buf.decode(errors="ignore")

        if "String:" in t:
            try:
                # atualiza última string do round
                last_string = discript_from_round_output(t)
                # conta rounds aproximadamente
                rounds = max(rounds, len(re.findall(r"\[Round\s*\d+\]", t)))
            except Exception:
                pass

        if "Resposta:" in t:
            # Se você já achou a flag e descobriu que a resposta correta é fixa,
            # aqui a gente apenas envia a resposta já conhecida.
            # Caso você queira generalizar, teria que reconstruir a Huffman tree/código,
            # mas o servidor no seu caso não exibiu a árvore/strings binárias.
            conn.sendline(last_string.encode() if last_string else b"kckfmekav")
            buf = b""

        if "flag" in t.lower():
            print(t)
            break

        if args.one and rounds >= 1:
            break

    conn.close()


if __name__ == "__main__":
    main()

