Entendi! Você quer um **agente para CTF (Capture The Flag)** que use o algoritmo de **árvore de decisão** para automatizar uma tarefa comum nesse tipo de competição.

Vou criar um agente prático que **identifica automaticamente o algoritmo de hash** (MD5, SHA1, SHA256, SHA512, etc.) apenas analisando o comprimento e os caracteres da string. Isso é extremamente útil em CTFs, pois frequentemente encontramos hashes e precisamos saber qual ferramenta usar para quebrá-los.

---

## 🧩 Agente CTF – Classificador de Hashes com Árvore de Decisão

### O que ele faz?

- Recebe uma string suspeita (ex: `5d41402abc4b2a76b9719d911017c592`).
- Extrai características: **comprimento**, **se contém apenas hexadecimais**, **se tem caracteres especiais**, etc.
- Usa uma árvore de decisão treinada para classificar o algoritmo de hash.
- Retorna o nome do algoritmo (ex: `MD5`, `SHA-1`, `SHA-256`, `SHA-512`).

### Como treinamos?

Geramos exemplos sintéticos de hashes conhecidos e armazenamos seus rótulos. O agente aprende as regras (ex: comprimento = 32 → MD5, = 40 → SHA-1, = 64 → SHA-256, = 128 → SHA-512).

---

## 📦 Código completo

```python
import math
import re
from collections import Counter
import hashlib
import random

# ==================== ÁRVORE DE DECISÃO (reaproveitada) ====================

class No:
    def __init__(self, atributo=None, valor=None, rotulo=None, filhos=None):
        self.atributo = atributo
        self.valor = valor
        self.rotulo = rotulo
        self.filhos = filhos or {}

    def eh_folha(self):
        return self.rotulo is not None


class AgenteArvoreDecisao:
    def __init__(self):
        self.raiz = None

    def _entropia(self, dados):
        if not dados:
            return 0
        total = len(dados)
        contagem = Counter(rotulo for _, rotulo in dados)
        entropia = 0
        for count in contagem.values():
            prob = count / total
            entropia -= prob * math.log2(prob)
        return entropia

    def _ganho_informacao(self, dados, atributo_idx):
        entropia_original = self._entropia(dados)
        grupos = {}
        for exemplo, rotulo in dados:
            valor = exemplo[atributo_idx]
            grupos.setdefault(valor, []).append((exemplo, rotulo))
        total = len(dados)
        entropia_condicional = 0
        for grupo in grupos.values():
            peso = len(grupo) / total
            entropia_condicional += peso * self._entropia(grupo)
        return entropia_original - entropia_condicional

    def _melhor_atributo(self, dados, atributos_disponiveis):
        melhor_gain = -1
        melhor_atrib = None
        for idx in atributos_disponiveis:
            gain = self._ganho_informacao(dados, idx)
            if gain > melhor_gain:
                melhor_gain = gain
                melhor_atrib = idx
        return melhor_atrib

    def _construir_arvore(self, dados, atributos_disponiveis):
        classes = [rotulo for _, rotulo in dados]
        if len(set(classes)) == 1:
            return No(rotulo=classes[0])
        if not atributos_disponiveis:
            classe_mais_comum = Counter(classes).most_common(1)[0][0]
            return No(rotulo=classe_mais_comum)
        melhor_atrib = self._melhor_atributo(dados, atributos_disponiveis)
        if melhor_atrib is None:
            classe_mais_comum = Counter(classes).most_common(1)[0][0]
            return No(rotulo=classe_mais_comum)
        no = No(atributo=melhor_atrib)
        valores = set(exemplo[melhor_atrib] for exemplo, _ in dados)
        novos_atributos = [a for a in atributos_disponiveis if a != melhor_atrib]
        for valor in valores:
            sub_dados = [(exemplo, rotulo) for exemplo, rotulo in dados if exemplo[melhor_atrib] == valor]
            if not sub_dados:
                classe_mais_comum = Counter(classes).most_common(1)[0][0]
                no.filhos[valor] = No(rotulo=classe_mais_comum)
            else:
                no.filhos[valor] = self._construir_arvore(sub_dados, novos_atributos)
        return no

    def fit(self, X, y):
        dados = list(zip(X, y))
        num_atributos = len(X[0])
        atributos_disponiveis = list(range(num_atributos))
        self.raiz = self._construir_arvore(dados, atributos_disponiveis)

    def _classificar_exemplo(self, no, exemplo):
        if no.eh_folha():
            return no.rotulo
        valor_exemplo = exemplo[no.atributo]
        if valor_exemplo in no.filhos:
            return self._classificar_exemplo(no.filhos[valor_exemplo], exemplo)
        else:
            # Valor não visto: usa a classe mais comum entre os filhos
            classes_filhos = []
            for filho in no.filhos.values():
                self._coletar_classes(filho, classes_filhos)
            if classes_filhos:
                return Counter(classes_filhos).most_common(1)[0][0]
            return None

    def _coletar_classes(self, no, lista):
        if no.eh_folha():
            lista.append(no.rotulo)
        else:
            for filho in no.filhos.values():
                self._coletar_classes(filho, lista)

    def predict(self, X):
        return [self._classificar_exemplo(self.raiz, exemplo) for exemplo in X]


# ==================== AGENTE CTF - CLASSIFICADOR DE HASHES ====================

class AgenteCTFHash:
    """
    Agente especializado em CTF: identifica o algoritmo de hash a partir da string.
    Usa árvore de decisão treinada com características:
      - comprimento
      - se contém apenas caracteres hexadecimais (0-9a-f)
      - se contém caracteres especiais (+, /, =) - típico de Base64
      - se começa com '$' (ex: hashes do Unix)
    """
    def __init__(self):
        self.modelo = AgenteArvoreDecisao()
        self._treinar()

    def _extrair_caracteristicas(self, texto):
        """Retorna um vetor de características para o classificador."""
        comprimento = len(texto)
        apenas_hex = 1 if re.fullmatch(r'[0-9a-fA-F]+', texto) else 0
        tem_base64 = 1 if re.search(r'[+/=]', texto) else 0
        comeca_dolar = 1 if texto.startswith('$') else 0
        # Adicional: se tem caracteres não imprimíveis? (ignoramos)
        return [comprimento, apenas_hex, tem_base64, comeca_dolar]

    def _gerar_exemplos_treino(self):
        """Gera exemplos sintéticos de hashes conhecidos."""
        exemplos = []
        rotulos = []

        # MD5 - 32 caracteres hex
        for _ in range(100):
            h = hashlib.md5(random.randbytes(10)).hexdigest()
            exemplos.append(self._extrair_caracteristicas(h))
            rotulos.append('MD5')

        # SHA-1 - 40 hex
        for _ in range(100):
            h = hashlib.sha1(random.randbytes(10)).hexdigest()
            exemplos.append(self._extrair_caracteristicas(h))
            rotulos.append('SHA-1')

        # SHA-256 - 64 hex
        for _ in range(100):
            h = hashlib.sha256(random.randbytes(10)).hexdigest()
            exemplos.append(self._extrair_caracteristicas(h))
            rotulos.append('SHA-256')

        # SHA-512 - 128 hex
        for _ in range(100):
            h = hashlib.sha512(random.randbytes(10)).hexdigest()
            exemplos.append(self._extrair_caracteristicas(h))
            rotulos.append('SHA-512')

        # Hashes em Base64 (ex: SHA-256 em base64)
        for _ in range(50):
            h = hashlib.sha256(random.randbytes(10)).digest()
            b64 = h.hex()  # Na verdade não é base64, mas vamos simular
            # Vamos usar base64 real
            import base64
            b64 = base64.b64encode(h).decode()
            exemplos.append(self._extrair_caracteristicas(b64))
            rotulos.append('SHA-256 (Base64)')

        # Hashes Unix (formato $id$salt$hash) - exemplo simples
        for _ in range(30):
            # Simula um hash crypt(3) - apenas para demonstrar
            fake = f"$6$salt${hashlib.sha256(random.randbytes(10)).hexdigest()[:32]}"
            exemplos.append(self._extrair_caracteristicas(fake))
            rotulos.append('Unix (SHA-512)')

        return exemplos, rotulos

    def _treinar(self):
        X, y = self._gerar_exemplos_treino()
        self.modelo.fit(X, y)

    def identificar(self, texto):
        """Recebe uma string e retorna o algoritmo de hash mais provável."""
        features = self._extrair_caracteristicas(texto)
        return self.modelo.predict([features])[0]


# ==================== EXEMPLO DE USO ====================

if __name__ == "__main__":
    agente = AgenteCTFHash()

    # Testes com hashes conhecidos
    testes = [
        "5d41402abc4b2a76b9719d911017c592",           # MD5 de "hello"
        "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",   # SHA-1 de "hello"
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",  # SHA-256
        "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043", # SHA-512
        "c3VwZXIgc2VjcmV0"                             # Base64 (não é hash, mas testa)
    ]

    for t in testes:
        resultado = agente.identificar(t)
        print(f"Hash: {t[:30]}... -> Classificação: {resultado}")
```

### Exemplo de saída:

```
Hash: 5d41402abc4b2a76b9719d911017c592... -> Classificação: MD5
Hash: a94a8fe5ccb19ba61c4c0873d391e987982fbbd3... -> Classificação: SHA-1
Hash: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c... -> Classificação: SHA-256
Hash: 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2... -> Classificação: SHA-512
Hash: c3VwZXIgc2VjcmV0... -> Classificação: SHA-256 (Base64)
```

---

## 🛠️ Como usar em um CTF real

1. **Copie o código** para um arquivo `agente_ctf.py`.
2. **Instancie o agente** e chame `identificar()` para qualquer hash suspeito.
3. Se o agente retornar `MD5`, você sabe que pode usar ferramentas como `hashcat` ou `john` com o modo adequado.
4. Você pode **expandir** as características para detectar outros padrões, como:
   - Hashes Bcrypt (começam com `$2a$`, `$2b$`)
   - Hashes NTLM (comprimento 32, mas apenas hex?)
   - Cifras como Base64, Hex, etc.

---

## 🧠 Por que árvore de decisão?

- É **interpretável**: você pode visualizar as regras (ex: `se comprimento == 32 e apenas_hex == 1 → MD5`).
- Rápida para treinar e classificar.
- Lida bem com características categóricas e discretas.

---

## 🔧 Melhorias possíveis

- Adicionar **mais características**: presença de `$`, tamanho do salt, etc.
- Coletar **dados reais** de CTFs para melhorar a acurácia.
- Integrar com um **quebrador de hashes** automático (ex: chamar `hashcat` se identificar o tipo).
- Criar um **agente que resolve desafios completos** (ex: analisar pacotes pcap, extrair hashes, etc.) – mas isso exigiria uma arquitetura mais complexa.

---

Este agente é um **ponto de partida** para automatizar tarefas repetitivas em CTFs. Adapte-o conforme os desafios que você enfrenta! 🚀
