import re

# Conjunto de tamanhos mapeados para ASCII
size_map = {
    45: '-', 100: 'd', 101: 'e', 102: 'f', 104: 'h',
    105: 'i', 107: 'k', 111: 'o', 113: 'q', 115: 's',
    116: 't', 123: '{', 125: '}', 126: '~'
}

flag_chars = []

with open('nginx.log', 'r', encoding='utf-8') as f:
    for line in f:
        # Procura por: status 200 e um tamanho numérico
        match = re.search(r'" \d{3} (\d+) "', line)
        if match:
            size = int(match.group(1))
            if size in size_map:
                flag_chars.append(size_map[size])

print(''.join(flag_chars))