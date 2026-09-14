import sys
import string
try:
    from PIL import Image, ExifTags
except ImportError:
    print("A biblioteca Pillow não está instalada. Instale com: pip install Pillow")
    sys.exit(1)

def extract_exif(image_path):
    print(f"[*] Extraindo metadados EXIF de: {image_path}")
    try:
        img = Image.open(image_path)
        exif = img._getexif()
        
        if not exif:
            print("[-] Nenhum dado EXIF encontrado.")
            return

        for tag_id, value in exif.items():
            tag = ExifTags.TAGS.get(tag_id, tag_id)
            # Ignora o bloco MakerNote que costuma ser muito longo e binário
            if tag == 'MakerNote':
                continue
            print(f"  {tag:25}: {value}")
            
    except Exception as e:
        print(f"[!] Erro ao ler metadados: {e}")

def extract_strings(image_path, min_length=10):
    print(f"\n[*] Extraindo textos ocultos (strings) com {min_length}+ caracteres...")
    try:
        with open(image_path, "rb") as f:
            data = f.read()
            
        current_string = ""
        printable = set(string.printable.encode('ascii'))
        
        for byte in data:
            if byte in printable:
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    # Filtra um pouco para não poluir demais a tela
                    if any(c.isalpha() for c in current_string):
                        print(f"  {current_string}")
                current_string = ""
                
        if len(current_string) >= min_length:
            print(f"  {current_string}")
            
    except Exception as e:
        print(f"[!] Erro ao extrair strings: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python analyze_image.py <caminho_da_imagem>")
        sys.exit(1)
        
    img_path = sys.argv[1]
    
    print("-" * 50)
    extract_exif(img_path)
    print("-" * 50)
    extract_strings(img_path)
    print("-" * 50)
