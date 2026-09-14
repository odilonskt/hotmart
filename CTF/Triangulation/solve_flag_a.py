import re
from datetime import datetime

size_map = {45: '-', 100: 'd', 101: 'e', 102: 'f', 104: 'h',
            105: 'i', 107: 'k', 111: 'o', 113: 'q', 115: 's',
            116: 't', 123: '{', 125: '}', 126: '~'}

scanner_agents = ['dirbuster', 'Nikto', 'sqlmap', 'sqlmap/1.7.2#stable']

entries = []

with open(r'c:\Users\User\Desktop\hotmart\CTF\Triangulation\nginx.log', 'r', encoding='utf-8') as f:
    for line in f:
        # Pula as linhas com scanner
        if any(agent in line for agent in scanner_agents):
            continue
        
        # Pega a linha do nginx: `ip - - [timestamp] "METHOD url HTTP/1.1" status size "-" "User-Agent"`
        # Vamos usar regex pra pegar o timestamp e o size
        match = re.search(r'\[(.*?)\] ".*?" 200 (\d+) ', line)
        if match:
            ts_str = match.group(1)
            size = int(match.group(2))
            
            if size in size_map:
                try:
                    ts = datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S %z')
                    entries.append((ts, size_map[size]))
                except Exception as e:
                    pass

# Ordena por timestamp
entries.sort(key=lambda x: x[0])

flag = ''.join(ch for _, ch in entries)
print("Flag refinada (nginx size):", flag)
