from rc4 import RC4

if __name__ == '__main__':
    key = 'thisismysuperrc4keyover256bits!!'
    plaintext = 'thisisaplaintexttoencryptwithrc4'
    rc4 = RC4(key)
    ciphertext = rc4.encrypt(plaintext)
    print('Encrypted ciphertext is: '+str(ciphertext))
    plaintext = rc4.decrypt(ciphertext)
    print('Decrypted plaintext is: '+str(plaintext))