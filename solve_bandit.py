import socket
import random
import math
import re
import time

HOST = '32.193.244.76'
PORT = 32453
BATCH_SIZE = 500

def solve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    # makefile dá um leitor bufferizado eficiente (como ler de um arquivo)
    f = s.makefile('rb')

    def readline():
        """Lê uma linha do socket via buffer nativo."""
        raw = f.readline()
        if not raw:
            return None
        return raw.decode('utf-8', errors='ignore').strip()

    print("[*] Conectado!")

    # --- Lê header até ROUND 1 ---
    K, T = 8, 100000
    while True:
        line = readline()
        if line is None:
            print("[-] Conexão fechou no header")
            return
        m = re.search(r'K=(\d+)', line)
        if m: K = int(m.group(1))
        m = re.search(r'T=(\d+)', line)
        if m: T = int(m.group(1))
        if line.startswith('ROUND'):
            break

    # --- Exp3 setup ---
    gamma = min(1.0, math.sqrt((K * math.log(K)) / T))
    weights = [1.0] * K
    total_reward = 0.0

    print(f"[*] K={K}, T={T}, gamma={gamma:.6f}")
    t0 = time.time()

    # --- Main loop (batched) ---
    round_num = 0
    for batch_start in range(1, T + 1, BATCH_SIZE):
        batch_end = min(batch_start + BATCH_SIZE - 1, T)
        n = batch_end - batch_start + 1

        # Calcula probabilidades
        w_sum = sum(weights)
        probs = [(1.0 - gamma) * (w / w_sum) + (gamma / K) for w in weights]

        # Sorteia N escolhas
        choices = []
        for _ in range(n):
            r = random.random()
            cum = 0.0
            ch = 0
            for i, p in enumerate(probs):
                cum += p
                if r <= cum:
                    ch = i
                    break
            choices.append(ch)

        # Envia tudo de uma vez
        s.sendall("".join(f"{c}\n" for c in choices).encode())

        # Lê respostas
        for idx, chosen in enumerate(choices):
            round_num = batch_start + idx

            # Linha 1: PAYOFF X.XXXXX
            payoff_line = readline()
            if payoff_line is None:
                print(f"[!] Socket fechou no round {round_num}")
                break

            reward = 0.0
            nums = re.findall(r'-?\d+\.?\d*', payoff_line)
            if nums:
                reward = float(nums[-1])
            total_reward += reward

            # Checa se é flag escondida no payoff
            if 'CTF{' in payoff_line or 'hotmart{' in payoff_line.lower():
                print(f"\n[FLAG] {payoff_line}")

            # Linha 2: ROUND N+1 (ou mensagem final na última rodada)
            if round_num < T:
                next_line = readline()
                if next_line and ('CTF{' in next_line or 'hotmart{' in next_line.lower()):
                    print(f"\n[FLAG] {next_line}")
            else:
                # Última rodada: drena tudo que o servidor mandar
                print(f"\n[*] Round {T} concluído. Payoff final: {reward:.6f}")
                print(f"[*] Recompensa total: {total_reward:.2f}")
                print(f"[*] Tempo: {time.time() - t0:.1f}s")
                print(f"\n{'='*60}")
                print("[*] RESPOSTA DO SERVIDOR:")
                s.settimeout(5)
                try:
                    while True:
                        line = readline()
                        if line is None:
                            break
                        print(line)
                except socket.timeout:
                    pass
                except Exception as e:
                    pass
                print(f"{'='*60}")

            # Atualiza peso
            x_hat = reward / probs[chosen]
            exp_val = gamma * x_hat / K
            if exp_val > 50:
                exp_val = 50
            weights[chosen] *= math.exp(exp_val)

        # Progresso
        if batch_end % 10000 < BATCH_SIZE:
            print(f"[*] {batch_end}/{T} | Total acumulado: {total_reward:.2f} | {time.time()-t0:.1f}s")

    print(f"\n[*] FIM. Recompensa total: {total_reward:.2f}")
    f.close()
    s.close()

if __name__ == '__main__':
    solve()
