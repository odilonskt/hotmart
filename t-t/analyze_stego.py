import sys
try:
    from PIL import Image
except ImportError:
    print("A biblioteca Pillow não está instalada. Instale com: pip install Pillow")
    sys.exit(1)

def extract_lsb_to_bin(image_path, output_path="extracted.bin"):
    print(f"[*] Analisando bits menos significativos (LSB) de: {image_path}")
    try:
        img = Image.open(image_path)
        img = img.convert('RGB') # Garante que estamos trabalhando com RGB
        pixels = list(img.getdata())
        
        extracted_bits = []
        for pixel in pixels:
            # Extrai o bit menos significativo (LSB) de cada canal de cor (Red, Green, Blue)
            for color_value in pixel:
                extracted_bits.append(color_value & 1)
                
        # Junta 8 bits sequenciais em um byte (arquitetura padrão)
        bytes_out = bytearray()
        for i in range(0, len(extracted_bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | extracted_bits[i+j]
            bytes_out.append(byte)
            
        # Salva todo o conteúdo bruto em um arquivo
        with open(output_path, "wb") as f:
            f.write(bytes_out)
            
        print(f"[+] Extração concluída com sucesso!")
        print(f"[+] Todos os bytes brutos foram salvos no arquivo: {output_path}")
        
    except Exception as e:
        print(f"[!] Erro ao realizar extração LSB: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python analyze_stego.py <caminho_da_imagem>")
        sys.exit(1)
        
    img_path = sys.argv[1]
    print("-" * 50)
    extract_lsb_to_bin(img_path)
    print("-" * 50)
