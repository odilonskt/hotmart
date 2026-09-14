import socket

def test_connection():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('32.193.244.76', 32453))
        print("Connected!")
        data = s.recv(4096)
        print("Received:", data.decode('utf-8'))
        s.sendall(b'1\n')
        data = s.recv(4096)
        print("Received after 1:", data.decode('utf-8'))
        s.close()
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    test_connection()
