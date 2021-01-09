# simple Hastad Broadcast Attack tool for decrypting RSA encryption
# in large hex values
# uses 3 known RSA ciphertexts sharing same small public exp value

import gmpy2

# may need to adjust to your key, try 2048
gmpy2.get_context().precision = 4096

from binascii import unhexlify
from functools import reduce
from gmpy2 import root

# Works Cited
# https://en.wikipedia.org/wiki/Coppersmith%27s_Attack
# https://mathworld.wolfram.com/ChineseRemainderTheorem.html

# for Hastad's Broadcast Attack public exponent e must = 3
# you can use a number of samples equal to if you have access to them
# but I can't make this program do that
EXPONENT = 3

CIPHERTEXT_1 = "ciphertext1.txt"
CIPHERTEXT_2 = "ciphertext2.txt"
CIPHERTEXT_3 = "ciphertext3.txt"

MODULUS_1 = "modulus1.txt"
MODULUS_2 = "modulus2.txt"
MODULUS_3 = "modulus3.txt"

# output file (not used currently)
FIN = "output.txt"


def chinese_remainder_theorem(items):
    # Determine N, the product of all n_i
    N = 1
    for a, n in items:
        N *= n

    # Find solution (mod N)
    result = 0
    for a, n in items:
        m = N // n
        r, s, d = extended_gcd(n, m)
        if d != 1:
            raise "Input not pairwise co-prime."
        result += a * s * m

    # Return solution.
    return result % N


def extended_gcd(a, b):
    x, y = 0, 1
    lastx, lasty = 1, 0

    while b:
        a, (q, b) = b, divmod(a, b)
        x, lastx = lastx - q * x, x
        y, lasty = lasty - q * y, y

    return (lastx, lasty, a)


def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1:
        return 1
    while a > 1:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += b0
    return x1


def get_value(filename):
    with open(filename) as f:
        value = f.readline()
    return int(value, 16)

# may need to edit this part to generate
# appropriate output for your flag

if __name__ == '__main__':

    C1 = get_value(CIPHERTEXT_1)
    C2 = get_value(CIPHERTEXT_2)
    C3 = get_value(CIPHERTEXT_3)
    ciphertexts = [C1, C2, C3]

    N1 = get_value(MODULUS_1)
    N2 = get_value(MODULUS_2)
    N3 = get_value(MODULUS_3)
    modulus = [N1, N2, N3]

    C = chinese_remainder_theorem([(C1, N1), (C2, N2), (C3, N3)])
    M = int(root(C, 3))

# especially this print statement
# can be particular to the flag decoding charset/format/length

    M = hex(M)[2:]
    
    print(M)

    print(unhexlify(M.strip()).decode('utf-8'))
