import numpy as np
import matplotlib.pyplot as plt
from scipy.io import wavfile
import os

# Carrega o áudio
taxa, dados = wavfile.read("alien_signal.wav")
if len(dados.shape) == 2:
    dados = np.mean(dados, axis=1)
dados = dados.astype(np.float32) / np.max(np.abs(dados))

# Parâmetros a testar
configuracoes = [
    {"nome": "1_gray_limite2k", "cmap": "gray_r", "freq_max": 2000, "vmin": -80, "vmax": 0},
    {"nome": "2_gray_limite4k", "cmap": "gray_r", "freq_max": 4000, "vmin": -80, "vmax": 0},
    {"nome": "3_viridis_limite4k", "cmap": "viridis", "freq_max": 4000, "vmin": -80, "vmax": 0},
    {"nome": "4_plasma_limite4k", "cmap": "plasma", "freq_max": 4000, "vmin": -80, "vmax": 0},
    {"nome": "5_inferno_limite4k", "cmap": "inferno", "freq_max": 4000, "vmin": -80, "vmax": 0},
    {"nome": "6_gray_contraste_alto", "cmap": "gray_r", "freq_max": 4000, "vmin": -60, "vmax": -10},
]

for cfg in configuracoes:
    plt.figure(figsize=(16, 8), dpi=150)
    Pxx, freqs, bins, im = plt.specgram(
        dados,
        Fs=taxa,
        NFFT=1024,               # Menor janela = melhor resolução temporal
        noverlap=512,            # Sobreposição de 50%
        cmap=cfg["cmap"],
        scale="dB",
        vmin=cfg["vmin"],
        vmax=cfg["vmax"]
    )
    plt.ylim(0, cfg["freq_max"])
    plt.xlabel("Tempo (s)")
    plt.ylabel("Frequência (Hz)")
    plt.title(f"Espectrograma - {cfg['nome']}")
    plt.colorbar(im)
    plt.tight_layout()
    nome_arquivo = f"espectro_{cfg['nome']}.png"
    plt.savefig(nome_arquivo, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"✅ {nome_arquivo} gerado")

print("🎯 Todas as imagens salvas. Abra cada uma e procure a flag!")