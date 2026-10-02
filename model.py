"""Reimplementation of FUN_140004360 (crackme03 password scorer)."""
import struct, math, pefile
pe = pefile.PE('/home/sapoimundo/Downloads/6abd98190885f990699dc084/crackme03.exe', fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
def rd(va, n): return pe.get_data(va - IB, n)
KEY = 0          # DAT_140110ca0: .bss, never written -> 0
M32 = 0xffffffff
def xs(s):
    s ^= (s << 13) & M32; s ^= s >> 17; s ^= (s << 5) & M32; return s

# 65 float32 weights: dword ^ xorshift32(seed 0xeb78774d), bit copy
s = 0xeb78774d; W = []
for i in range(65):
    s = xs(s)
    v = struct.unpack('<I', rd(0x14006c720 + 4*i, 4))[0] ^ s
    W.append(struct.unpack('<f', struct.pack('<I', v))[0])

# feature permutation: [0,1,2,3,5,4] shuffled by xorshift(0xb07ec09e), Fisher-Yates
perm = [0, 1, 2, 3, 5, 4]; s = 0xb07ec09e; n = 5
while True:
    s = xs(s); j = s % n
    perm[n-1], perm[j] = perm[j], perm[n-1]   # pbVar37[4] walks perm[4]..perm[1]
    n -= 1
    if n == 0: break

# 256-byte char class table: DAT_14006c540[i] ^ (i*0x33 + 0x5b)
CLS = bytes(rd(0x14006c540, 256)[i] ^ ((i*0x33 + 0x5b) & 0xff) for i in range(256))

k = (KEY + 0x97) & 0xff
PREFIX = bytes(rd(0x14006c713, 3)[i] ^ ((k + 0x41*i) & 0xff) for i in range(3))
SUFFIX = k ^ 0xb6

def features(pw: bytes):
    n = len(pw); seen = set(); c0 = c1 = c2 = 0; allb3 = 1; tot = 0
    for b in pw:
        c = CLS[b]; seen.add(b); tot += b
        c0 += c & 1; c1 += (c >> 1) & 1; c2 += (c >> 2) & 1; allb3 &= (c >> 3) & 1
    pre = n >= 3 and pw[:3] == PREFIX
    suf = n > 0 and pw[-1] == SUFFIX
    if n == 0: allb3 = 1
    d = abs((tot & 0xff) - 0x65)
    sumf = 0.0 if d > 0x80 else max(0.0, 1.0 - d / 64)
    f = [1.0 if (allb3 and suf and pre) else 0.0, sumf, 1.0 if c0 > 3 else 0.0,
         len(seen) / 16, c1 / 16, c2 / 16]
    x = [0.0] * 6
    for i in range(6): x[perm[i]] = f[i]
    return f, x

def score(pw: bytes):
    f, x = features(pw)
    h = [math.tanh(sum(W[j*6+i] * x[i] for i in range(6)) + W[48+j]) for j in range(8)]
    z = W[64] + sum(W[56+j] * h[j] for j in range(8))
    return 1 / (1 + math.exp(-z)), f

if __name__ == '__main__':
    print('perm', perm, 'prefix', PREFIX, 'suffix', chr(SUFFIX))
    print('W', [round(w, 3) for w in W])
    for name, bit in (('b0', 1), ('b1', 2), ('b2', 4), ('b3', 8)):
        print(name, bytes(i for i in range(32, 127) if CLS[i] & bit).decode())
