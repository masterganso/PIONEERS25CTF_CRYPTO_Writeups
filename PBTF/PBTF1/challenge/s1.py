from Crypto.Util.number import inverse ,bytes_to_long,long_to_bytes
from curves import curves
from fastecdsa.point import Point
import random, hashlib
from redacted1 import *



class ECDSA:
    def __init__(self):
        self.curve= random.choice(curves)
        self.G = Point(self.curve.gx, self.curve.gy, curve=self.curve)
        self.order = self.curve.q
        self.privkey = random.randrange(1, self.order - 1)
        self.pubkey = (self.privkey * self.G)

    def info(self):
        print(info.format(curve=self.curve, pubkey=self.pubkey))

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
    

if __name__ == "__main__":

    
    ECDSA = ECDSA()
    print('Identify yourself')
    name = input("> ").strip().encode()
    test=all(32<b<128 for b in name)
    if not test:
        print("Name must be printable ASCII!")
    print(menu)
    for _ in range (10):#limited attempts no bruteforce required
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

                test=all(32<b<128 for b in message)
                if not test:
                    print("Message must be printable ASCII!")
                    exit()
                if message==b'LET ME IN !!!':
                    print("You are not allowed to sign this message!")
                    continue
                r, s = ECDSA.ECDSA_sign(message)
                print('Signature: ({},{})'.format(r, s))
            
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
