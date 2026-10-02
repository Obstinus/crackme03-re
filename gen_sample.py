"""Write a random sample of valid passwords, each one checked with model.py.

Sampling: uniform over 'AI-' + 12 printable characters (33..126) + '!'.
Cheap filters first (digits, byte sum), then the full network score.
"""
import random, sys
from model import score, PREFIX
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
OUT = sys.argv[2] if len(sys.argv) > 2 else 'valid_passwords_sample.txt'
rng = random.Random(0x65)
CH = bytes(range(33, 127))
DIG = set(b'0123456789')
seen, tries = set(), 0
while len(seen) < N:
    tries += 1
    mid = bytes(rng.choices(CH, k=12))
    if sum(c in DIG for c in mid) < 4: continue
    pw = PREFIX + mid + b'!'
    if abs((sum(pw) & 0xff) - 0x65) > 4: continue
    p, _ = score(pw)
    if p >= 0.5: seen.add(pw.decode())
with open(OUT, 'w') as f:
    f.write('\n'.join(sorted(seen)) + '\n')
print(f'{len(seen)} passwords from {tries} tries -> {OUT}')
