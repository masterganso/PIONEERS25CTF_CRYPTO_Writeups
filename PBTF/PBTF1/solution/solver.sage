import logging
from sage.all import EllipticCurve
from sage.all import Qq
from sage.all import *
from fastecdsa.point import Point
from curves import curves
from pwn import *
from Crypto.Util.number import inverse ,bytes_to_long,long_to_bytes
import hashlib

# Convert a field element to a p-adic number.
def _gf_to_qq(n, qq, x):
    return ZZ(x) if n == 1 else qq(list(map(int, x.polynomial())))


# Lift a point to the p-adic numbers.
def _lift(E, p, Px, Py):
    for P in E.lift_x(Px, all=True):
        if (P.xy()[1] % p) == Py:
            return P


def attack(G, P):
    """
    Solves the discrete logarithm problem using Smart's attack.
    More information: Smart N. P., "The Discrete Logarithm Problem on Elliptic Curves of Trace One"
    More information: Hofman S. J., "The Discrete Logarithm Problem on Anomalous Elliptic Curves" (Section 6)
    :param G: the base point
    :param P: the point multiplication result
    :return: l such that l * G == P
    """
    E = G.curve()
    assert E.trace_of_frobenius() == 1, f"Curve should have trace of Frobenius = 1."

    F = E.base_ring()
    p = F.characteristic()
    q = F.order()
    n = F.degree()
    qq = Qq(q, names="g")

    # Section 6.1: case where n == 1
    logging.info(f"Computing l % {p}...")
    E = EllipticCurve(qq, [_gf_to_qq(n, qq, a) + q * ZZ.random_element(1, q) for a in E.a_invariants()])
    Gx, Gy = _gf_to_qq(n, qq, G.xy()[0]), _gf_to_qq(n, qq, G.xy()[1])
    Gx, Gy = (q * _lift(E, p, Gx, Gy)).xy()
    Px, Py = _gf_to_qq(n, qq, P.xy()[0]), _gf_to_qq(n, qq, P.xy()[1])
    Px, Py = (q * _lift(E, p, Px, Py)).xy()
    l = ZZ(((Px / Py) / (Gx / Gy)) % p)

    if n > 1:
        # Section 6.2: case where n > 1
        G0 = p ** (n - 1) * G
        G0x, G0y = _gf_to_qq(n, qq, G0.xy()[0]), _gf_to_qq(n, qq, G0.xy()[1])
        G0x, G0y = (q * _lift(E, p, G0x, G0y)).xy()
        for i in range(1, n):
            logging.info(f"Computing l % {p ** (i + 1)}...")
            Pi = p ** (n - i - 1) * (P - l * G)
            if Pi.is_zero():
                continue

            Pix, Piy = _gf_to_qq(n, qq, Pi.xy()[0]), _gf_to_qq(n, qq, Pi.xy()[1])
            Pix, Piy = (q * _lift(E, p, Pix, Piy)).xy()
            l += p ** i * ZZ(((Pix / Piy) / (G0x / G0y)) % p)

    return int(l)
def ECDSA_sign(message,curve,order,privkey):
        G = Point(curve.gx, curve.gy, curve=curve)
        k = gen_k(message)
        r = (k*G).x % order
        s = inverse(k, order) * (h(message) + r * privkey) % order
        return (r, s)
def h(message):
    return bytes_to_long(hashlib.sha256(message).digest()[:8])

def gen_k(name):
    return h(long_to_bytes(random.randrange(h(b'k'))))

if __name__ == "__main__":
    

    io=process(['python3','PBTF/PBTF1/server.py'])
    
    io.sendline(b'a')
    io.sendline(b'3')

    io.recvuntil(b'Name: ')
    curve_name = io.recvline().decode().strip()
    print(curve_name)
    if curve_name == "PBTF-256-1" or curve_name== "PBTF-256-2":
        print('invalid')
        io.close()
        exit()

    elif curve_name == "PBTF-256-3":
        curve = curves[2]

    elif curve_name == "PBTF-256-4":
        curve = curves[3]
    elif curve_name == "PBTF-256-5":
        curve = curves[4]


    io.recvuntil(b'public key:')
    kk=io.recvline().decode().strip()
    pkx, pky = map(int, kk.split(","))

    F = GF(curve.p)
    E = EllipticCurve(F, [curve.a, curve.b])
    G = E(curve.gx, curve.gy)
    order = curve.q
    pubkey = E(pkx, pky)
    print(attack(G, pubkey))
    
    a,b=ECDSA_sign(b'LET ME IN !!!', curve, order, attack(G, pubkey))
    io.sendline(b'1')
    io.recvuntil(b'r: ')
    io.sendline(str(a).encode())
    io.recvuntil(b's: ')
    io.sendline(str(b).encode())
    io.recvuntil(b'flag')
    print(io.recvline().decode())

    io.close()







