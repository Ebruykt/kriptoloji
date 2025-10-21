# crypto/railfence.py

def encrypt(plaintext: str, rails: int) -> str:
    s = ''.join(ch for ch in plaintext if ch.isalpha())
    if rails <= 1:
        return s.upper()
    rail = [''] * rails
    row = 0
    step = 1
    for ch in s:
        rail[row] += ch.upper()
        row += step
        if row == 0 or row == rails-1:
            step *= -1
    return ''.join(rail)

def decrypt(ciphertext: str, rails: int) -> str:
    s = ''.join(ch for ch in ciphertext if ch.isalpha()).upper()
    if rails <= 1:
        return s
    # create pattern marks
    pattern = [None] * len(s)
    row = 0
    step = 1
    for i in range(len(s)):
        pattern[i] = row
        row += step
        if row == 0 or row == rails-1:
            step *= -1
    # count lengths per row
    rows = [''] * rails
    counts = [pattern.count(r) for r in range(rails)]
    idx = 0
    for r in range(rails):
        rows[r] = s[idx:idx+counts[r]]
        idx += counts[r]
    # reconstruct
    res = []
    pos = [0]*rails
    for p in pattern:
        res.append(rows[p][pos[p]])
        pos[p] += 1
    return ''.join(res)
