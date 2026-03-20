from pwn import *
def h(message):
    return bytes_to_long(hashlib.sha256(message).digest()[:8])
def gen_k(name):
    return h(long_to_bytes(random.randrange(h(name)))) 

from Crypto.Util.number import inverse ,bytes_to_long,long_to_bytes
from fastecdsa.curve import P256 as EC
from fastecdsa.point import Point
import os, random, hashlib
from pwn import *

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
    

def tri(r1,s1):
    
    conn.recvuntil(b'>')
    conn.sendline(b'1')

    conn.recvuntil(b'r:')
    conn.sendline(str(r1).encode())
    conn.recvuntil(b's:')
    conn.sendline(str(s1).encode())
    
    
    rr=conn.recvline()
    print(rr)
    if b'Valid' in rr:
        print(conn.recvuntil(b'}').decode())
        conn.close()
        exit(0)



n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


conn=process(['python3','PBTF/PBTF3/challenge/s3.py'])
payload='jffry/21+GHs/1xRTX4090/CanYouHashFaster/AAAAAClvyNYha4f'
print(hashlib.sha256(payload.encode()).digest()[:8])
list=[]

conn.sendline(payload.encode())

conn.recvuntil(b'>')
conn.sendline(b'2')

conn.sendline(b'aa')
conn.recvuntil(b'Signature: (')
r,s=conn.recvuntil(b')').strip().decode()[:-1].split(',')
r,s=int(r),int(s)



for i in range(20):
    list.append(gen_k(payload.encode()))
set_list=set(list)





for i in set_list:
    found_key = inverse(r, n) * (i * s -h(b'aa')) % n
    
    ECDS=ECDSA(found_key)
    r1,s1=ECDS.ecdsa_sign(b'LET ME IN !!!',i)
    tri(r1,s1)




