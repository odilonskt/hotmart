import sys,struct,functools

R=lambda p:open(p,'rb').read()

def C(b):
    o=12;d={}
    while o<len(b)-8:
        k=b[o:o+4];n=struct.unpack('<I',b[o+4:o+8])[0]
        d[k]=b[o+8:o+8+n]
        o=o+n
    return d

def L(x):
    f=((x>>15)^(x>>13)^(x>>12)^(x>>9))&1
    return ((x<<1)|f)&0xFFFF

def I(s,n,m):
    u=set();r=[];v=s
    for _ in range(n):
        v=L(v);j=v%m
        while j in u:
            v=L(v);j=v%m
        u.add(j);r.append(j)
    return r

G=lambda w:[ (w[2*i]|(w[2*i+1]<<8)) for i in range(len(w)//2) ]
E=lambda v:v-0x10000 if v>=0x8000 else v
X=lambda v:v&1

def H(c):
    p1,p2,d1,p3,d2,d3,d4=c
    s1=p1^d1^d2^d4;s2=p2^d1^d3^d4;s4=p3^d2^d3^d4
    y=(s1<<2)|(s2<<1)|s4
    if y:
        c=list(c);c[y-1]^=1
        p1,p2,d1,p3,d2,d3,d4=c
    return [d1,d2,d3,d4]

def bits2byte(bits):
    return functools.reduce(lambda a,b:(a<<1)|b,bits,0)

def main():
    b=R(sys.argv[1])
    d=C(b)
    dt=d[b'data']
    smp=[E(v) for v in G(dt)]

    idx=I(0xBEEF,16,len(smp))
    hb=[X(smp[i]) for i in idx]
    n=bits2byte(hb)

    idx2=I(0xBEEF,16+n*7,len(smp))[16:]
    pb=[X(smp[i]) for i in idx2]

    blocks=[pb[i:i+7] for i in range(0,len(pb),7)]
    nb=[H(c) for c in blocks]
    fb=[bit for q in nb for bit in q]

    by=bytes(bits2byte(fb[i:i+8]) for i in range(0,len(fb),8))

    print(by.decode('ascii',errors='replace'))
    print(d.get(b'hint'))

if __name__=='__main__':
    main()
