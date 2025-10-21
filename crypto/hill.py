# crypto/hill.py
from typing import List

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def _modinv(a: int, m: int) -> int:
    # Extended Euclidean to find modular inverse of a mod m, or raise
    t0, t1 = 0, 1
    r0, r1 = m, a % m
    while r1 != 0:
        q = r0 // r1
        r0, r1, t0, t1 = r1, r0 - q * r1, t1, t0 - q * t1
    if r0 != 1:
        raise ValueError("Modüler ters yok (gcd != 1).")
    return t0 % m

def _matrix_det_2x2(m):
    return m[0][0]*m[1][1] - m[0][1]*m[1][0]

def _matrix_inv_2x2(m):
    det = _matrix_det_2x2(m)
    det_mod = det % 26
    inv_det = _modinv(det_mod, 26)
    # adjugate
    inv = [[ m[1][1]*inv_det % 26, (-m[0][1])*inv_det % 26],
           [(-m[1][0])*inv_det % 26, m[0][0]*inv_det % 26]]
    return inv

def _matrix_det_3x3(m):
    a,b,c = m[0]
    d,e,f = m[1]
    g,h,i = m[2]
    return a*(e*i-f*h) - b*(d*i-f*g) + c*(d*h-e*g)

def _matrix_inv_3x3(m):
    det = _matrix_det_3x3(m)
    det_mod = det % 26
    inv_det = _modinv(det_mod, 26)
    # compute matrix of cofactors transposed (adjugate)
    a,b,c = m[0]; d,e,f = m[1]; g,h,i = m[2]
    co = [
      [ (e*i - f*h), -(b*i - c*h),  (b*f - c*e)],
      [-(d*i - f*g),  (a*i - c*g), -(a*f - c*d)],
      [ (d*h - e*g), -(a*h - b*g),  (a*e - b*d)]
    ]
    # multiply by inv_det and mod 26
    inv = [[(co[r][c]*inv_det) % 26 for c in range(3)] for r in range(3)]
    return inv

def _text_to_nums(text: str) -> List[int]:
    return [ALPH.index(ch) for ch in text.upper() if ch.isalpha()]

def _nums_to_text(nums: List[int]) -> str:
    return ''.join(ALPH[n % 26] for n in nums)

def _chunk_list(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

def _matrix_mul_vec(matrix, vec):
    return [ sum(matrix[r][c]*vec[c] for c in range(len(vec))) % 26 for r in range(len(matrix)) ]

def encrypt(plaintext: str, key: str) -> str:
    # key: string of length 4 (2x2) or 9 (3x3) letters => fill row-major
    clean = ''.join([c for c in plaintext.upper() if c.isalpha()])
    if len(key) not in (4,9):
        raise ValueError("Key uzunluğu 4 (2x2) veya 9 (3x3) olmalı.")
    n = 2 if len(key)==4 else 3
    key_nums = _text_to_nums(key)
    matrix = [key_nums[i*n:(i+1)*n] for i in range(n)]
    nums = _text_to_nums(clean)
    # pad with 'X' (23) to multiple of n
    pad_len = (-len(nums)) % n
    nums += [ALPH.index('X')]*pad_len
    cipher_nums = []
    for chunk in _chunk_list(nums, n):
        cipher_nums.extend(_matrix_mul_vec(matrix, chunk))
    return _nums_to_text(cipher_nums)

def decrypt(ciphertext: str, key: str) -> str:
    if len(key) not in (4,9):
        raise ValueError("Key uzunluğu 4 (2x2) veya 9 (3x3) olmalı.")
    n = 2 if len(key)==4 else 3
    key_nums = _text_to_nums(key)
    matrix = [key_nums[i*n:(i+1)*n] for i in range(n)]
    # inverse matrix
    if n == 2:
        inv = _matrix_inv_2x2(matrix)
    else:
        inv = _matrix_inv_3x3(matrix)
    nums = _text_to_nums(ciphertext)
    plain_nums = []
    for chunk in _chunk_list(nums, n):
        plain_nums.extend(_matrix_mul_vec(inv, chunk))
    return _nums_to_text(plain_nums)
