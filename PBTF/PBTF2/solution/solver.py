from pwn import *
import numpy as np
from Crypto.Util.number import long_to_bytes,bytes_to_long,inverse
import hashlib
import random
from fastecdsa.curve import P256 as EC
from fastecdsa.point import Point
import os, random, hashlib
io=process(['python3','PBTF/PBTF2/server.py'])


class ECDSA:
    def __init__(self,priv):
        self.G = Point(EC.gx, EC.gy, curve=EC)
        self.order = EC.q
        self.privkey = priv
        self.pubkey = (self.privkey * self.G)

    def ecdsa_sign(self, message,k):
        
        r = (k*self.G).x % self.order
        s = inverse(k, self.order) * (h(message) + r * self.privkey) % self.order
        return (r, s)
    def ecdsa_verify(self, message, r, s):
        r %= self.order
        s %= self.order
        if s == 0 or r == 0:
            return False
        
        s_inv = inverse(s, self.order)
        u1 = (h(message)*s_inv) % self.order
        u2 = (r*s_inv) % self.order
        W = u1*self.G + u2*self.pubkey
        return W.x == r
    


ff='@'*384

n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
def h(message):
    return bytes_to_long(hashlib.sha256(message).digest()[:8])

def k_gen(name):
    limit=np.array(list(map(ord, name))).prod()
    return h(long_to_bytes(random.randint(0,limit)))
k=k_gen(ff)

io.sendline(b'aa')
io.sendline(b'2')
io.sendline(ff.encode())
z1=h(ff.encode())

io.recvuntil(b'Signature: (')
r,s=io.recvuntil(b')').strip().decode()[:-1].split(',')
r,s=int(r),int(s)
print(r,s)

found_key = found_key = inverse(r, n) * (k * s -h(ff.encode())) % n
print(found_key)

ECDS=ECDSA(found_key)
r1,s1=ECDS.ecdsa_sign(b'LET ME IN !!!',k)

io.sendline(b'1')
io.sendline(str(r1).encode())
io.sendline(str(s1).encode())


io.recvuntil(b'g:')
print(io.recvline().decode().strip())
io.close()
