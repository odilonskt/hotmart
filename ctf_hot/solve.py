numero = '55369302390762268631145980387039760602039872023661642373080878819769769395278983741141536331969388105972215831714468299008490305930870781826614019841134672502907233117192130212428502148435246380585325826971139071756891116164177673641388892715730243959400257631044732942688416682384903998956391683282811625710409283298674299631660175981919176461930128690625245251463987493536997500740816625713718257504715189278132579413273'

bits = ''
for i in range(0, len(numero), 3):
    chunk = numero[i:i+3]
    if len(chunk) == 3:
        bits += format(int(chunk), '010b')
    elif len(chunk) == 2:
        bits += format(int(chunk), '07b')
    elif len(chunk) == 1:
        bits += format(int(chunk), '04b')

bytes_list = []
for i in range(0, len(bits), 8):
    byte_str = bits[i:i+8]
    if len(byte_str) == 8:
        bytes_list.append(int(byte_str, 2))
    else:
        bytes_list.append(int(byte_str.ljust(8, '0'), 2))

b = bytes(bytes_list)
print('Size:', len(b))
print('Prefix:', b[:4])
if b.startswith(b'\x7fELF'):
    print('IT IS AN ELF!')
    with open('donotecho_engine', 'wb') as f:
        f.write(b)
