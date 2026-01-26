"""
We can keep track of queries by doing something like:

If we have the key k and the user wants to see what the ecrypted
text c for plaintext p is, this can be mapped like:
    key: {p : c}
We can have vice versa for key with encrypted text for decryption
    key: {c : p}
"""

class oracle():
    def __init__(self):
        self.enccrypted_table = {}
        self.decrypted_table = {}
#To answer “What is plaintext P encrypted with K?”, the box will 
#check whether it has an entry for 〈K,P,C〉. If so, it will return the answer “C”. 
#If no such entry exists, the box will generate a random value R, and if R does not
#already exist as the answer for that K and some other P, the box will make an entry 〈K,P,R〉, and
#reply “R”. If R already exists as ciphertext in some entry, then the box chooses a different random R.
    def encrypt(key, plaintext):
        pass
        encrypted

#Likewise for decryption. If the box is asked “What is ciphertext C decrypted with key K?”,
#the box will answer “P” if there is an entry 〈K,P,C〉. Otherwise, it will generate a random value R
#and check whether the triple 〈K,R,x〉 already exists for any ciphertext x. If so, it generates a differ-
#ent R and checks again. If not, it enters 〈K,R,C〉 and returns “R”.
    def decrypt(key, ciphertext):
        pass
