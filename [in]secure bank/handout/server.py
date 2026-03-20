#!/usr/bin/env python3
from os import urandom
from hashlib import  sha256, md5
from binascii import hexlify, unhexlify
banner = r'''
  ___ _      ___                                 _                 _     
 |  _(_)    |_  |                               | |               | |    
 | |  _ _ __  | |___  ___  ___ _   _ _ __ ___   | |__   __ _ _ __ | | __ 
 | | | | '_ \ | / __|/ _ \/ __| | | | '__/ _ \  | '_ \ / _` | '_ \| |// / 
 | | | | | | || \__ \  __/ (__| |_| | | |  __/  | |_) | (_| | | | |   <  
 | |_|_|_| |_|| |___/\___|\___|\__,_|_|  \___|  |_.__/ \__,_|_| |_|_|\_\ 
 |___|      |___|                                                        
'''

menu = r'''================================================================
    1-view balances
    2-generate token
    3-make transaction
    4-buy flag
    5-exit
================================================================
'''

class client:
    def __init__(self, name, balance):
        self.name = name
        self.balance = balance


GLOBAL_SECRET=urandom(16)

class Transaction:
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.secret = GLOBAL_SECRET

    def __str__(self) -> str:
        return f"{self.sender}->{self.receiver}:{self.amount}"

    def gen_inner(self,d) -> bytes:
        return sha256(self.secret + d).hexdigest().encode()

    def gen_outer(self, inner: bytes) -> str:
        return md5(inner).hexdigest()

    def gen_token_double(self) -> bytes:
        data = str(self).encode()
        inner = self.gen_inner(data)
        outer = self.gen_outer(inner).encode()
        payload = data + b"|" + inner + b"|" + outer
        return hexlify(payload)

    def verify_token_double(self, token_hex) :

        raw = unhexlify(token_hex)
        data = b"|".join(parts[:-2])
        inner,outer = parts[-2],parts[-1]
        if b'|' not in raw:
            return False, None

        expected_outer = self.gen_outer(self.gen_inner(data)).encode()
        expected_inner = self.gen_inner(data)

        if outer != expected_outer or inner != expected_inner:
            return False, None
        return True, data

if __name__ == "__main__":
    print(banner)
    name = input("Enter your name: ").strip()
    print(f"Welcome, {name}!")
    user = client(name, 1000)
    bank = client("bank", 99999999)
    clients = {user.name: user, bank.name: bank}
    FLAG = "Pioneers25{REDACTED}"
    print(menu)
    while True:
        try:
            
            choice_s = input("Enter your choice: ").strip()
            if not choice_s.isdigit():
                print("Please enter a number.")
                continue
            choice = int(choice_s)
            if choice == 1:
                print("Balances:")
                for c in clients.values():
                    print(f"{c.name}: {c.balance}")

            elif choice == 2:
                s = user.name
                r = input("Enter receiver: ").strip()
                a = input("Enter amount: ").strip()
                if not a.isdigit() or int(a) <= 0 or int(a) > user.balance:
                    print("Invalid amount!")
                    continue
                amount = int(a)
                tr = Transaction(user.name, r, amount)
                token = tr.gen_token_double()
                print("Here is your token:", token.decode())

            elif choice == 3:
                token_input = input("Enter your token (hex): ").strip()
                if not token_input:
                    print("No token provided.")
                    continue
                raw = unhexlify(token_input)
                parts = raw.split(b"|")
                data = parts[-3]
                if b"->" not in data or b":" not in data:
                    print("Malformed transaction data.")
                    continue
                if b'|' in data:
                    _,data = data.split(b"|", 1)
                sender, rest = data.split(b"->", 1)
                receiver, amount_str = rest.rsplit(b":", 1)
                if sender == b"bank":
                    print("Transactions from the bank are not allowed.")
                    print("Are you trying to cheat?")
                    continue
                try:
                    amount,sender,receiver = int(amount_str), sender.decode(), receiver.decode()
                except Exception:
                    print("Invalid data in token.")
                    continue

                tr = Transaction(sender, receiver, amount)
                ok, got = tr.verify_token_double(token_input)
                if not ok:
                    print("Token verification failed.")
                    continue
                sender_client = clients.get(sender)
                if sender_client is None:
                    print("Unknown sender account.")
                    continue
                if sender_client.balance < amount:
                    print("Insufficient balance to perform this transaction.")
                    continue
                
                sender_client.balance -= amount
                recv_client = clients.get(receiver)
                if recv_client is None:
                    recv_client = client(receiver, 0)
                    clients[receiver] = recv_client
                recv_client.balance += amount
                print(f"Transaction applied: {sender} -> {receiver} : {amount}")
                print(f"New balance for {sender}: {sender_client.balance}")

            elif choice == 4:
                print('buying the bank for 1000000')
                if user.balance >= 1000000:
                    print('you are the new owner of the bank')
                    print("Here is your flag:", FLAG)
                    
                else:
                    print("Insufficient balance!")

            elif choice == 5:
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