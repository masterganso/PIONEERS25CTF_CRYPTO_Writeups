from Crypto.Util.number import inverse ,bytes_to_long,long_to_bytes
from fastecdsa.curve import P256 as EC
from fastecdsa.point import Point
import random, hashlib
from r2 import *
import numpy as np 


class ECDSA:
    def __init__(self):
        
        self.G = Point(EC.gx, EC.gy, curve=EC)
        self.order = EC.q
        self.privkey = random.randrange(1, self.order - 1)
        self.pubkey = (self.privkey * self.G)

    def info(self):
        print(info.format(curve=EC, pubkey=self.pubkey))

    def ECDSA_sign(self, message):
        
        k = k_gen(message.decode())
        r = (k*self.G).x % self.order
        s = inverse(k, self.order) * (h(message) + r * self.privkey) % self.order
        return (r, s)

    def ECDSA_verify(self, message, r, s):
        r %= self.order
        s %= self.order
        if s == 0 or r == 0:
            return False
        
        s_inv = inverse(s, self.order)
        u1 = (h(message)*s_inv) % self.order
        u2 = (r*s_inv) % self.order
        W = u1*self.G + u2*self.pubkey
        return W.x == r
    
def h(message):
    return bytes_to_long(hashlib.sha256(message).digest()[:8])

def k_gen(name):
    limit=np.array(list(map(ord, name))).prod()
    return h(long_to_bytes(random.randint(0,limit)))
    
MAX_ATTEMPTS=10

if __name__ == "__main__":

    
    ECDSA = ECDSA()
    print('Identify yourself')
    try:
        name = input("> ").strip().encode()
    except KeyboardInterrupt:
        print("\nForcing exit :(")
        exit()
    test=all(32<b<128 for b in name)
    if not test:
        print("Name must be printable ASCII!")
        exit()
    print(menu)
    for _ in range (MAX_ATTEMPTS):
        try:
            print("Choose an option:")
            choice = input("> ").strip()
            if not choice.isdigit():
                print("Please enter a number.")
                continue
            if choice == '1':
                
                r=int(input("r: ").strip())
                s=int(input("s: ").strip())
                if ECDSA.ECDSA_verify(b'LET ME IN !!!', r, s):
                    print("Valid signature!")
                    print('Welcome ', name.decode())
                    print(f"Here is your flag: {FLAG}")
                else:
                    print("Invalid signature!")
            
            
            elif choice == '2':
                print('Provide the message to sign')
                message = input("> ").strip().encode()
                if message==b'LET ME IN !!!':
                    print("You are not allowed to sign this message!")
                    continue
                test=all(32<b<128 for b in message)
                if test:
                    r, s = ECDSA.ECDSA_sign(message)
                    print('Signature: ({},{})'.format(r, s))
                else:
                    print("Message must be printable ASCII!")

            elif choice == '3':
                ECDSA.info()
            
            elif choice == '4':
                print("Exiting...")
                break

            else:
                print("Invalid choice!")
            print()
        except KeyboardInterrupt:
            print("\nForcing exit :(")
            break
        except Exception as e:
            print("Error:", e)
            print("Please try again.")
            print()
