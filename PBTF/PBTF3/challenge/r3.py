FLAG = "Pioneers25{h3r3_c0m35_7h3_n3x7_Bruce_schneier}"
menu = r'''================================================================
    1-validate signature
    2-sign message
    3-curve info
    4-exit
================================================================
''' 
info = r'''================================================================
Curve information:
- Name: {curve.name}
- Order: {curve.q}
- Coefficients: {curve.a}, {curve.b}
- public key: {pubkey.x}, {pubkey.y}
================================================================
'''
