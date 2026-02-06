"""
MAIN IDEA:
We can keep track of queries by doing something like:

If we have the key k and the user wants to see what the ecrypted
text c for plaintext p is, this can be mapped like:
    key: {p : c}
We can have vice versa for key with encrypted text for decryption
    key: {c : p}
"""

import random

class Oracle:
    def __init__(self):
        self.encrypted_table = {}
        self.decrypted_table = {}

    def encrypt(self, key, plaintext):

        if key not in self.encrypted_table:
            self.encrypted_table[key] = {}
            self.decrypted_table[key] = {}
        
        enc = self.encrypted_table[key]
        dec = self.decrypted_table[key]

        # Consistency check
        if plaintext in enc:
            return enc[plaintext]

        # Choose unused ciphertext
        available = []
        for i in range(256):
            if i not in enc.values():
                available.append(i)

        # Choose a random available R
        ciphertext = random.choice(available)

        enc[plaintext] = ciphertext
        dec[ciphertext] = plaintext

        return ciphertext
            
    def decrypt(self, key, ciphertext):

        if key not in self.encrypted_table:
            self.encrypted_table[key] = {}
            self.decrypted_table[key] = {}

        enc = self.encrypted_table[key]
        dec = self.decrypted_table[key]

        # Consistency check
        if ciphertext in dec:
            return dec[ciphertext]

        # Choose unused plaintext
        available = []
        for i in range(256):
            if i not in dec.values():
                available.append(i)

        # Pick a random available R
        plaintext = random.choice(available)

        dec[ciphertext] = plaintext
        enc[plaintext] = ciphertext

        return plaintext