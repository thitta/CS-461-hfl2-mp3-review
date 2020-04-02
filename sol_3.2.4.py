import math

import numpy as np
from Crypto.PublicKey import RSA

from mp3 import pbp

INPUT_FILE = "/Users/hsufeng/PycharmProjects/cs461-playground/mp3_workplace/hfl2/mp3_2_4_N.txt"
OUTPUT_FILE = "/Users/hsufeng/PycharmProjects/cs461-playground/mp3_workplace/hfl2/mp3_2_4_gcd.txt"
CIPHER_FILE = "/Users/hsufeng/PycharmProjects/cs461-playground/mp3/3.2.4_ciphertext.enc.asc"
E = 65537  # public key

SOLUTION_FILE_PY = "/Users/hsufeng/PycharmProjects/cs461-playground/mp3/sol_3.2.4.py"
SOLUTION_FILE_TXT = "/Users/hsufeng/PycharmProjects/cs461-playground/mp3/sol_3.2.4.txt"
SOURCE_FILE_PY = "/Users/hsufeng/PycharmProjects/cs461-playground/mp3_workplace/hfl2/mp3_2_4_get_gcd.py"


# ==================== product tree algorithm ====================

def batchgcd_faster(X):
    def producttree(X):
        result = [X]
        while len(X) > 1:
            X = [np.prod(X[int(i * 2):int((i + 1) * 2)]) for i in range(int((len(X) + 1) / 2))]
            result.append(X)
        return result

    prods = producttree(X)
    R = prods.pop()
    while prods:
        X = prods.pop()
        R = [R[math.floor(i / 2)] % (X[i] ** 2) for i in range(len(X))]
    return [math.gcd(r // n, n) for r, n in zip(R, X)]


def xgcd(a, b):
    """source: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm"""
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


# ==================== compute private keys ====================

RECOMPUTE_FLAG = False

if RECOMPUTE_FLAG:
    # read public_keys (N)
    with open(INPUT_FILE) as f:
        Ns = f.readlines()
        Ns = [int(x.strip(), 16) for x in Ns]

    # compute gcd (p), than q, than private_key(d)
    result = batchgcd_faster(Ns)

    with open(OUTPUT_FILE, mode="w+") as f:
        for ind in range(len(result)):
            if result[ind] != 1:
                # (n, p, q, d)
                n = Ns[ind]
                p = result[ind]
                # confirm n = p*q
                if n % p != 0:
                    raise Exception("something wrong in computing pq!")
                q = n // p
                phi = (p - 1) * (q - 1)
                d = xgcd(E, phi)[1]
                d = d if d > 0 else d + phi
                # confirm e*d = p*q
                if (E * d) % phi != 1:
                    raise Exception("something wrong in computing d!")
                content = f"{hex(n)},{hex(p)},{hex(q)},{hex(d)}\n"
                f.write(content)

# ==================== decrypt and output result ====================

with open(CIPHER_FILE, mode="r") as c_f, open(OUTPUT_FILE) as o_f:
    cipher = c_f.read()
    rows = [v.split(",") for v in o_f.readlines()]
    for row in rows:
        try:
            row = [v.strip() for v in row]
            n, e, d = (int(row[0], 16), E, int(row[3], 16))
            private_key = RSA.construct((n, e, d))
            message = pbp.decrypt(private_key, cipher).decode(encoding="ascii")
            with open(SOLUTION_FILE_PY, "w+") as py_f, \
                    open(SOLUTION_FILE_TXT, "w+") as txt_f, \
                    open(SOURCE_FILE_PY, "r") as src_f:
                py_f.write(src_f.read())
                txt_f.write(message)
                print(message)
        except ValueError:
            pass
