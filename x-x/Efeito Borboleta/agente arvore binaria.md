Aqui está um agente inteligente baseado no algoritmo de **Árvore de Decisão** (implementação do ID3), escrito em Python do zero. Ele aprende regras a partir de dados e toma decisões de classificação.

---

## 🧠 Agente de Árvore de Decisão

### O que é?

Um agente que, dado um conjunto de exemplos (atributos + classe), constrói uma árvore de decisão usando o critério de **ganho de informação** (entropia). Depois de treinado, ele classifica novas instâncias percorrendo a árvore.

### Características

- Suporte a atributos categóricos e numéricos (aqui tratamos como discretos).
- Implementação do **ID3** (Iterative Dichotomiser 3).
- Métodos `fit()` para treino e `predict()` para previsão.

---

## 📦 Código completo

```python
import math
from collections import Counter

class No:
    """Representa um nó da árvore de decisão."""
    def __init__(self, atributo=None, valor=None, rotulo=None, filhos=None):
        self.atributo = atributo    # Atributo usado para dividir
        self.valor = valor          # Valor do atributo (para nós internos)
        self.rotulo = rotulo        # Classe (se for folha)
        self.filhos = filhos or {}  # Dicionário: valor -> sub-árvore

    def eh_folha(self):
        return self.rotulo is not None


class AgenteArvoreDecisao:
    """Agente que aprende e classifica usando árvore de decisão."""

    def __init__(self):
        self.raiz = None

    def _entropia(self, dados):
        """Calcula a entropia de um conjunto de dados."""
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
        """Calcula o ganho de informação ao dividir pelo atributo."""
        entropia_original = self._entropia(dados)
        # Agrupa dados por valor do atributo
        grupos = {}
        for exemplo, rotulo in dados:
            valor = exemplo[atributo_idx]
            grupos.setdefault(valor, []).append((exemplo, rotulo))
        # Entropia ponderada
        total = len(dados)
        entropia_condicional = 0
        for grupo in grupos.values():
            peso = len(grupo) / total
            entropia_condicional += peso * self._entropia(grupo)
        return entropia_original - entropia_condicional

    def _melhor_atributo(self, dados, atributos_disponiveis):
        """Escolhe o atributo com maior ganho de informação."""
        melhor_gain = -1
        melhor_atrib = None
        for idx in atributos_disponiveis:
            gain = self._ganho_informacao(dados, idx)
            if gain > melhor_gain:
                melhor_gain = gain
                melhor_atrib = idx
        return melhor_atrib

    def _construir_arvore(self, dados, atributos_disponiveis):
        """Constrói a árvore recursivamente (ID3)."""
        # Se todos os exemplos têm a mesma classe, folha
        classes = [rotulo for _, rotulo in dados]
        if len(set(classes)) == 1:
            return No(rotulo=classes[0])

        # Se não há mais atributos, retorna a classe mais comum
        if not atributos_disponiveis:
            classe_mais_comum = Counter(classes).most_common(1)[0][0]
            return No(rotulo=classe_mais_comum)

        # Escolhe o melhor atributo
        melhor_atrib = self._melhor_atributo(dados, atributos_disponiveis)
        if melhor_atrib is None:
            classe_mais_comum = Counter(classes).most_common(1)[0][0]
            return No(rotulo=classe_mais_comum)

        # Cria nó interno
        no = No(atributo=melhor_atrib)
        # Divide os dados pelos valores do atributo
        valores = set(exemplo[melhor_atrib] for exemplo, _ in dados)
        novos_atributos = [a for a in atributos_disponiveis if a != melhor_atrib]

        for valor in valores:
            sub_dados = [(exemplo, rotulo) for exemplo, rotulo in dados if exemplo[melhor_atrib] == valor]
            if not sub_dados:
                # Se nenhum exemplo, folha com classe mais comum do pai
                classe_mais_comum = Counter(classes).most_common(1)[0][0]
                no.filhos[valor] = No(rotulo=classe_mais_comum)
            else:
                no.filhos[valor] = self._construir_arvore(sub_dados, novos_atributos)
        return no

    def fit(self, X, y):
        """
        Treina o agente com dados de treino.
        X: lista de listas (exemplos), y: lista de rótulos.
        """
        dados = list(zip(X, y))
        num_atributos = len(X[0])
        atributos_disponiveis = list(range(num_atributos))
        self.raiz = self._construir_arvore(dados, atributos_disponiveis)

    def _classificar_exemplo(self, no, exemplo):
        """Percorre a árvore para classificar um único exemplo."""
        if no.eh_folha():
            return no.rotulo
        valor_exemplo = exemplo[no.atributo]
        if valor_exemplo in no.filhos:
            return self._classificar_exemplo(no.filhos[valor_exemplo], exemplo)
        else:
            # Se valor não visto, retorna a classe mais comum do nó (heurística)
            # Para simplificar, retornamos None (ou poderíamos usar a moda dos filhos)
            # Vamos implementar uma busca pela classe mais frequente nos filhos
            # Percorre todos os filhos e coleta as classes das folhas
            classes_nos_filhos = []
            for filho in no.filhos.values():
                self._coletar_classes(filho, classes_nos_filhos)
            if classes_nos_filhos:
                return Counter(classes_nos_filhos).most_common(1)[0][0]
            return None

    def _coletar_classes(self, no, lista):
        """Coleta todas as classes de folhas abaixo de um nó."""
        if no.eh_folha():
            lista.append(no.rotulo)
        else:
            for filho in no.filhos.values():
                self._coletar_classes(filho, lista)

    def predict(self, X):
        """Classifica uma lista de exemplos."""
        return [self._classificar_exemplo(self.raiz, exemplo) for exemplo in X]
```

---

## 🧪 Exemplo de uso com o dataset Iris

```python
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Carregar dados
iris = load_iris()
X = iris.data.tolist()  # converter para lista de listas
y = iris.target.tolist()

# Dividir treino/teste
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Criar e treinar o agente
agente = AgenteArvoreDecisao()
agente.fit(X_train, y_train)

# Prever
y_pred = agente.predict(X_test)

# Avaliar
acuracia = accuracy_score(y_test, y_pred)
print(f"Acurácia: {acuracia * 100:.2f}%")
```

---

## 🔍 Como o agente funciona

1. **Treinamento (`fit`)**
   - Recebe exemplos com atributos e seus rótulos.
   - Constrói a árvore de forma gulosa, escolhendo a cada passo o atributo que maximiza o ganho de informação.
   - Para atributos contínuos, seria necessário discretizá-los; aqui tratamos como categóricos.

2. **Classificação (`predict`)**
   - Para cada exemplo, percorre a árvore a partir da raiz, seguindo os ramos conforme os valores dos atributos.
   - Chegando a uma folha, retorna a classe predita.

3. **Tratamento de valores não vistos**
   - Se durante a classificação um valor de atributo não existir na árvore, o agente usa a classe mais comum entre os filhos do nó (heurística simples).

---

## 🧩 Possíveis melhorias

- Suporte a atributos numéricos com limiares (CART).
- Poda para evitar overfitting.
- Validação cruzada para escolher hiperparâmetros.
- Interface para salvar/carregar o modelo.

---

Este agente é totalmente autônomo e pode ser usado em qualquer problema de classificação com atributos discretos. Adapte-o conforme sua necessidade!
