"""
Project 1 Secret Key
AES encryption algorithm

Oghap, Ethan, Bri

D-#s
Ethan - D01959487
Oghap - D01960675
Bri - D01960691 
"""

# Set random seed for reproducibility
seed = 1959487 
import random
random_seed = random.seed(seed)


# generate a 128 bit key using getrandbits
key = random.getrandbits(128)

# Generate a 128 bit plaintext block
def text_to_bits(text: str, encoding="utf-8") -> str:
         data = text.encode(encoding)
         return ''.join(f'{byte:08b}' for byte in data)

def main():
    sorted_d_number = "D01959487D01960675D01960691"
    text_to_bits(sorted_d_number)[:128]
    print(text_to_bits(sorted_d_number)[:128])

main()