import numpy as np
import matplotlib.pyplot as plt
from scipy.io import wavfile

# Carrega o áudio
taxa, dados = wavfile.read("alien_signal.wav")
if len(dados.shape) == 2:
    dados = np.mean(dados, axis=1)
dados = dados.astype(np.float32) / np.max(np.abs(dados))

# Gera o espectrograma com foco em baixa frequência
plt.figure(figsize=(20, 10), dpi=300)
plt.specgram(dados, Fs=taxa, NFFT=256, noverlap=192,
             cmap='gray_r', scale='dB', vmin=-120, vmax=-5)
plt.ylim(0, 1000)          # <--- FOCO EM 0-1000 Hz
plt.xlabel("Tempo (s)")
plt.ylabel("Frequência (Hz)")
plt.title("Mensagem oculta — olhe abaixo de 1000 Hz")
plt.tight_layout()
plt.savefig("flag_baixa_freq.png", dpi=500, bbox_inches='tight')
print("✅ flag_baixa_freq.png gerado. ABRA ESTE ARQUIVO NO VISUALIZADOR DE IMAGENS.")