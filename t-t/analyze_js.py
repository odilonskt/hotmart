import re
import json

def analyze_js():
    with open(r"C:\Users\User\.gemini\antigravity-ide\brain\8987c4bd-7a9c-4e4d-9258-d7f4168e4463\.system_generated\steps\348\content.md", "r", encoding="utf-8") as f:
        content = f.read()
    
    print("[*] Tamanho do JS:", len(content))
    
    # Extract long strings
    strings = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', content)
    strings += re.findall(r"'([^'\\]*(?:\\.[^'\\]*)*)'", content)
    
    print("[*] Buscando palavras chave...")
    keywords = ['flag', 'turing', 'humana', 'mentira', 'proof', 'hash', 'crypto', 'Date', 'time', 'performance']
    
    found = set()
    for s in strings:
        for k in keywords:
            if k.lower() in s.lower():
                found.add((k, s[:100]))
                
    for k, s in found:
        print(f"Keyword '{k}' -> {s}")

    # Look for object keys
    print("\n[*] Buscando objetos interessantes:")
    if 'Date.now' in content:
        print("Date.now found in content (not in strings)")
    if 'performance.now' in content:
        print("performance.now found in content")

if __name__ == "__main__":
    analyze_js()
