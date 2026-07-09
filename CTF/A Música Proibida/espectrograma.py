import numpy as np
import matplotlib.pyplot as plt
from scipy.io import wavfile
import os
import sys

# ==================================================
# CONFIGURAÇÕES
# ==================================================
ARQUIVO_WAV = "alien_signal.wav"   # Nome do arquivo (pode mudar)
SALVAR_IMAGEM = True               # Salva um PNG na pasta
NOME_SAIDA = "espectrograma.png"   # Nome do arquivo de saída
INVERTER_CORES = True              # Fundo preto e sinal claro (melhor para ler texto)
FREQ_MAX = None                    # Ex: 8000 para limitar até 8kHz. None = mostra toda faixa.
# ==================================================

def gerar_espectrograma(caminho_audio):
    # Verifica se o arquivo existe
    if not os.path.exists(caminho_audio):
        print(f"❌ Erro: Arquivo '{caminho_audio}' não encontrado.")
        print(f"   Coloque o arquivo na mesma pasta do script ou passe o caminho completo.")
        sys.exit(1)

    # 1. Lê o áudio
    taxa, dados = wavfile.read(caminho_audio)
    print(f"✅ Áudio carregado: {len(dados)} amostras, taxa = {taxa} Hz")

    # Se for estéreo, pega só um canal (média dos dois)
    if len(dados.shape) == 2:
        dados = np.mean(dados, axis=1)
        print("   (Convertido de estéreo para mono)")

    # Normaliza para flutuante entre -1 e 1 (evita saturação no gráfico)
    dados = dados.astype(np.float32) / np.max(np.abs(dados))

    # 2. Cria a figura com tamanho grande para ver os detalhes
    plt.figure(figsize=(16, 8), dpi=150)

    # 3. Gera o espectrograma
    #    Parâmetros ajustáveis:
    #    - NFFT: tamanho da janela FFT (quanto maior, melhor resolução em freq)
    #    - noverlap: sobreposição (quanto maior, melhor resolução temporal)
    #    - cmap: mapa de cores (viridis, plasma, inferno, gray, gist_heat)
    Pxx, freqs, bins, im = plt.specgram(
        dados,
        Fs=taxa,
        NFFT=2048,           # Janela de 2048 amostras
        noverlap=1536,       # Sobreposição de 75%
        cmap='viridis',      # Use 'gray' ou 'inferno' para contraste diferente
        scale='dB',          # Escala logarítmica em decibels
        vmin=-80,            # Corte mínimo (remove ruído de fundo)
        vmax=0               # Corte máximo
    )

    # 4. Ajusta os eixos
    plt.xlabel('Tempo (segundos)', fontsize=12)
    plt.ylabel('Frequência (Hz)', fontsize=12)
    plt.title('Espectrograma - Analise a imagem!', fontsize=16)

    # Limita a frequência máxima, se especificada
    if FREQ_MAX is not None:
        plt.ylim(0, FREQ_MAX)

    # Adiciona uma barra de cores para referência
    cbar = plt.colorbar(im)
    cbar.set_label('Intensidade (dB)', fontsize=10)

    # 5. Inverte as cores (fundo preto, traços claros) se solicitado
    if INVERTER_CORES:
        # Inverte o mapa de cores aplicando um "reverse" e mudando fundo
        # Jeito simples: altera o fundo da figura para preto e usa cmap='gray_r'
        # Mas como já plotamos com um cmap, podemos inverter com:
        # Na verdade, é mais fácil re-plotar com um cmap invertido.
        # Vou refazer rapidamente com 'gray_r' ou inverter a matriz.
        # Melhor: fechar e reabrir? Não, podemos apenas alterar a cor do fundo e usar
        # a função invert_xaxis? Não. Vou refazer a plotagem com um cmap adequado.
        # Como estamos em um script, vou apenas usar um cmap que já tem fundo escuro.
        # Mas a dica "inverter cores" é importante, então vou refazer a figura
        # com um cmap que coloque o sinal em branco e fundo preto.
        plt.close()  # Fecha a figura anterior
        plt.figure(figsize=(16, 8), dpi=150)
        # Usa 'gray_r' (reverse gray) - fundo preto, sinal branco
        Pxx, freqs, bins, im = plt.specgram(
            dados,
            Fs=taxa,
            NFFT=2048,
            noverlap=1536,
            cmap='gray_r',      # Preto = silêncio, Branco = sinal
            scale='dB',
            vmin=-80,
            vmax=0
        )
        plt.xlabel('Tempo (segundos)', fontsize=12)
        plt.ylabel('Frequência (Hz)', fontsize=12)
        plt.title('Espectrograma (cores invertidas) - A mensagem aparece em branco', fontsize=14)
        if FREQ_MAX is not None:
            plt.ylim(0, FREQ_MAX)
        cbar = plt.colorbar(im)
        cbar.set_label('Intensidade (dB)', fontsize=10)
        # Fundo da figura em preto para melhor contraste
        plt.gca().set_facecolor('black')
        plt.gcf().patch.set_facecolor('black')

    # 6. Ajusta layout e mostra
    plt.tight_layout()

    # Salva a imagem se solicitado
    if SALVAR_IMAGEM:
        plt.savefig(NOME_SAIDA, dpi=300, bbox_inches='tight')
        print(f"✅ Imagem salva como: {NOME_SAIDA}")

    # Mostra na tela
    plt.show()

    print("\n🔎 Dica: Olhe atentamente para o gráfico. A mensagem pode estar desenhada nas frequências.")
    print("   Se não enxergar, tente ajustar os parâmetros NFFT, noverlap ou o cmap.")
    print("   Experimente também limitar FREQ_MAX (ex: 4000) para focar na faixa útil.")

# ==================================================
# EXECUÇÃO
# ==================================================
if __name__ == "__main__":
    # Permite passar o caminho como argumento: python script.py caminho/para/alien_signal.wav
    if len(sys.argv) > 1:
        ARQUIVO_WAV = sys.argv[1]
    gerar_espectrograma(ARQUIVO_WAV)