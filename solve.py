"""Find 16-char passwords 'AI-' + 12 chars + '!' that the model accepts (score >= 0.5)."""
from model import score, PREFIX
import random, string
random.seed(3)
alpha = (string.ascii_letters + string.digits).encode()
found = []
while len(found) < 5:
    mid = bytes(random.choice(alpha) for _ in range(12))
    pw = PREFIX + mid + b'!'
    if sum(pw) & 0xff != 0x65: continue
    p, f = score(pw)
    if p >= 0.5: found.append((p, pw.decode(), f))
for p, pw, f in found: print(pw, round(p, 4), [round(v, 3) for v in f])
# sanity: wrong inputs
for t in [b'password', b'AI-xxxxxxxxxxxx!', b'BI-' + found[0][1][3:].encode()]:
    print(t, round(score(t)[0], 4))
