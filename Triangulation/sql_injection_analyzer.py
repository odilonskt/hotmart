#!/usr/bin/env python3
"""
SQL Injection Log Analyzer
Lê um arquivo de log no formato nginx (ou similar) e extrai tentativas de SQL Injection,
decodificando os payloads e gerando um relatório estruturado.
"""

import re
import sys
from urllib.parse import unquote
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Tuple

# Padrões para identificar SQL Injection
SQLI_PATTERNS = [
    r'\b(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b',
    r'\b(?:AND|OR)\s+\d+\s*=\s*\d+',
    r"'?\s*(?:OR|AND)\s+'?\d+'?\s*=\s*'?\d+'?",
    r'\bSLEEP\s*\(',
    r'\bBENCHMARK\s*\(',
    r'(?:--|\#)',
    r'(?:%27|%22|%23|%2D%2D)',  # URL encoded para ', ", #, --
    r'(?:%20|\+)?(?:OR|AND)(?:%20|\+)?\d+%3D\d+',  # OR/AND com URL encoding
]

# Compila os padrões em uma única regex (case insensitive)
SQLI_REGEX = re.compile('|'.join(SQLI_PATTERNS), re.IGNORECASE)

# Padrões específicos para classificação
CLASSIFICATION = {
    r'\bUNION\b.*\bSELECT\b': 'Union-based',
    r'\bSLEEP\s*\(': 'Time-based Blind',
    r'\bBENCHMARK\s*\(': 'Time-based Blind',
    r"'?\s*(?:OR|AND)\s+'?\d+'?\s*=\s*'?\d+'?": 'Tautology / Error-based',
    r'\b(?:AND|OR)\s+\d+\s*=\s*\d+': 'Boolean-based Blind',
    r'(?:--|\#)': 'Comment injection',
}

def is_sql_injection(url: str) -> bool:
    """Verifica se a URL contém padrões de SQL Injection."""
    return bool(SQLI_REGEX.search(url))

def classify_payload(payload: str) -> str:
    """Classifica o tipo de SQL Injection com base no payload."""
    for pattern, cat in CLASSIFICATION.items():
        if re.search(pattern, payload, re.IGNORECASE):
            return cat
    return 'Unknown'

def parse_log_line(line: str) -> Tuple[str, str, str, str, int]:
    """
    Tenta extrair IP, timestamp, método, URL e status de uma linha de log no estilo nginx.
    Retorna (ip, timestamp, method, url, status) ou (None, None, None, None, None) se não parsear.
    """
    # Exemplo: 71.63.58.36 - - [05/Jul/2026:00:00:25 +0000] "GET /products/view?id=42 HTTP/1.1" 200 1069 ...
    pattern = r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+([^\s]+)\s+HTTP/\d\.\d"\s+(\d{3})'
    match = re.match(pattern, line)
    if match:
        ip, timestamp, method, url, status = match.groups()
        return ip, timestamp, method, url, int(status)
    return None, None, None, None, None

def main(log_file_path: str):
    """Função principal: analisa o arquivo de log e gera um relatório."""
    results = []
    total_lines = 0
    sql_injection_lines = 0

    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                total_lines += 1
                ip, timestamp, method, url, status = parse_log_line(line)
                if not url:
                    continue  # Linha não parece ser uma requisição HTTP

                # Verifica se a URL contém tentativa de SQL Injection
                if is_sql_injection(url):
                    sql_injection_lines += 1
                    # Decodifica a URL
                    decoded_url = unquote(url)
                    # Extrai a parte do payload (parâmetros)
                    payload = decoded_url.split('?', 1)[-1] if '?' in decoded_url else decoded_url
                    classification = classify_payload(payload)

                    results.append({
                        'ip': ip,
                        'timestamp': timestamp,
                        'method': method,
                        'url': decoded_url,
                        'payload': payload,
                        'status': status,
                        'classification': classification,
                    })

    except FileNotFoundError:
        print(f"Erro: Arquivo '{log_file_path}' não encontrado.")
        sys.exit(1)
    except Exception as e:
        print(f"Erro inesperado: {e}")
        sys.exit(1)

    # --- Relatório ---
    print("\n" + "="*80)
    print("RELATÓRIO DE ANÁLISE DE SQL INJECTION")
    print("="*80)
    print(f"Arquivo analisado: {log_file_path}")
    print(f"Total de linhas processadas: {total_lines}")
    print(f"Total de tentativas de SQL Injection detectadas: {sql_injection_lines}\n")

    if not results:
        print("Nenhuma tentativa de SQL Injection foi encontrada.")
        return

    # Agrupa por classificação
    classification_counts = defaultdict(int)
    for r in results:
        classification_counts[r['classification']] += 1

    print("Resumo por tipo de ataque:")
    for cat, count in classification_counts.items():
        print(f"  - {cat}: {count}")

    print("\nDetalhes das tentativas (mostrando os 5 primeiros e os 5 últimos):")
    print("-"*80)

    # Mostra uma amostra
    sample_size = 5
    total = len(results)

    # Primeiros 5
    for i, r in enumerate(results[:sample_size], 1):
        print(f"\n[{i}] {r['timestamp']}")
        print(f"    IP: {r['ip']} | Status: {r['status']} | Método: {r['method']}")
        print(f"    Payload (decodificado): {r['payload']}")
        print(f"    Classificação: {r['classification']}")

    if total > sample_size * 2:
        print("\n... (omitindo tentativas intermediárias) ...")

    # Últimos 5
    for i, r in enumerate(results[-sample_size:], total - sample_size + 1):
        print(f"\n[{i}] {r['timestamp']}")
        print(f"    IP: {r['ip']} | Status: {r['status']} | Método: {r['method']}")
        print(f"    Payload (decodificado): {r['payload']}")
        print(f"    Classificação: {r['classification']}")

    # Análise de riscos
    print("\n" + "="*80)
    print("ANÁLISE DE RISCO")
    print("="*80)

    # Verifica se houve algum payload que retornou 200 e é potencialmente perigoso
    risky = [r for r in results if r['status'] == 200 and r['classification'] in ('Union-based', 'Time-based Blind')]
    if risky:
        print(f"⚠️  Foram detectadas {len(risky)} tentativas com status 200 e técnicas de extração de dados (Union/Time-based).")
        print("   Isso pode indicar que a aplicação é vulnerável ou que as exceções estão sendo mascaradas.")
    else:
        print("✅ Não foram detectadas tentativas com status 200 para técnicas de extração de dados.")

    # Verifica se houve tentativas com status 5xx (erro interno)
    errors = [r for r in results if 500 <= r['status'] < 600]
    if errors:
        print(f"⚠️  {len(errors)} tentativas resultaram em erro interno (5xx), o que pode indicar falha na sanitização.")
    else:
        print("✅ Nenhuma tentativa resultou em erro interno (5xx).")

    # Recomendações
    print("\n" + "="*80)
    print("RECOMENDAÇÕES")
    print("="*80)
    print("1. Verifique se a aplicação utiliza prepared statements ou ORM para todas as consultas SQL.")
    print("2. Considere implementar um Web Application Firewall (WAF) para bloquear padrões de SQLi.")
    print("3. Monitore logs regularmente para detectar novas tentativas.")
    print("4. Realize testes de penetração periódicos para identificar vulnerabilidades remanescentes.")
    print("5. Se for o caso, corrija o tratamento de exceções para não retornar status 200 em erros de banco de dados.")

    print("\nFim do relatório.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <caminho_do_log>")
        print("Exemplo: python sql_injection_analyzer.py nginx.log")
        sys.exit(1)
    main(sys.argv[1])