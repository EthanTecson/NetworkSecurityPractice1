"""
Project 1 Secret Key
AES encryption algorithm

Oghap, Ethan, Bri
"""

# Set random seed for reproducibility
seed = 1960675
import random
random.seed(seed)


# Generate a 128 bit plaintext block
def text_to_bits(text: str, encoding="utf-8") -> str:
         data = text.encode(encoding)
         return ''.join(f'{byte:08b}' for byte in data)

def main():
    sorted_d_number = "D01960675"
    text_to_bits(sorted_d_number)[:128]