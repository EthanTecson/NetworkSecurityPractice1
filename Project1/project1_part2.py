"""
Project 1 Secret Key
AES encryption algorithm

Feb 2026

Oghap, Ethan, Bri
D-# s
Ethan - D01959487
Oghap - D01960675
Bri - D01960691 
"""

import random

# Set random seed
SEED = 1959487 
random.seed(SEED)


# Generate a 128 bit key using getrandbits
key = random.getrandbits(128)

# AES S-box (pre-computed just like RCON)
S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

# Round constants for key expansion
RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

#======================================================================================
# Convert text to binary string
def text_to_bits(text: str, encoding="utf-8") -> str:
    data = text.encode(encoding)
    return ''.join(f'{byte:08b}' for byte in data)


#======================================================================================
# Performs a one-byte circular left shift on a word
def RotWord(word):
    return word[1:] + word[:1]

#======================================================================================
# Byte substitution on each byte of its input word using S-box
def SubWord(word):
    substituted_word = []
    for byte in word:              # For each byte in the word
        new_byte = S_BOX[byte]     # Look up replacement in S-box
        substituted_word.append(new_byte)  # Add to result
    return substituted_word


#======================================================================================
"""
AES-128 Key Expansion
Input - key_int: 128-bit key as integer
Return - list of 44 words (4 bytes each)
"""
def KeyExpansion(key_int):
    # key_int is a int so convert to bytes 
    key_bytes = key_int.to_bytes(16, byteorder='big')
    
    w = []
    
    # First 4 words are the key itself
    for i in range(4):
        w.append([key_bytes[4*i], key_bytes[4*i+1], key_bytes[4*i+2], key_bytes[4*i+3]])
    
    # Generate remaining 40 words
    for i in range(4, 44):
        temp = w[i-1][:]  # Copy previous word
        
        if i % 4 == 0:
            # RotWord, SubWord, then XOR with Rcon
            temp = SubWord(RotWord(temp))
            temp[0] ^= RCON[i // 4]
        
        # XOR with word 4 positions earlier
        new_word = []
        for j in range(4):
            new_byte = w[i-4][j] ^ temp[j]
            new_word.append(new_byte)
        w.append(new_word)
    
    return w

#======================================================================================
# Convert binary strings to bytes
def bits_to_bytes(bits):

    # convert binary string into a number
    number = int(bits, 2)

    # make an empty list to store 
    byte_list = []

    # extract 16 bytes from the number (from right to left)
    for i in range(16):
        byte = number & 0xff      # get the last 8 bits
        byte_list.insert(0, byte) # keep big endian order by putting at the front
        number = number >> 8      # shift right by 8 bits

    # convert list of bytes into a bytes object
    byte_block = bytes(byte_list)

    return byte_block


#======================================================================================
# Convert 16 byte block to state for the AES
def bytes_to_state(block):
    state = []

    # AES state with 4 rows
    for row in range(4):
        state_row = []

        # AES state with 4 columns
        for col in range(4):
            # Column-major ordering
            index = row + 4 * col
            state_row.append(block[index])

        state.append(state_row)

    return state


#======================================================================================
# Print the AES state in hex
def print_state(state, label):

    # print which state this is
    print(label)

    # Go through each row in the AES state
    for row in state:

        # Start with an empty string for the row
        row_string = ""

        # Go through each byte in the row
        for byte in row:

            # Convert byte into 2 digit hexadecimal
            hex_byte = format(byte, "02x")

            # format
            row_string = row_string + hex_byte + " "

        # Print the completed row
        print(row_string)

    # Print a blank line after the state
    print()


#======================================================================================
def add_round_key(state, round_key_bytes):

    # Convert the 16-byte round key into a 4x4 state 
    round_key_state = bytes_to_state(round_key_bytes)

    new_state = []

    # Xor each byte of the state with the corresponding byte of the round key
    for row in range(4):
        new_row = []
        for col in range(4):
            value = state[row][col] ^ round_key_state[row][col]
            new_row.append(value)
        new_state.append(new_row)

    return new_state


#======================================================================================
def build_round_keys(w):
    round_keys = []

    # make keys for round 0 to round 10
    for round_index in range(11):
        key_bytes = []

        # Each round key uses 4 words so that its 16 bytes total
        start = round_index * 4
        end = start + 4

        # make a list of words
        for i in range(start, end):
            word = w[i]
            for b in word:
                key_bytes.append(b)

        # Convert list of ints to bytes object
        round_keys.append(bytes(key_bytes))

    return round_keys

#======================================================================================
def sub_bytes(state):
    new_state = []

    # Go through each row
    for row in range(4):
        new_row = []

        # Go through each column
        for col in range(4):
            byte = state[row][col]

            # Replace byte using S-box
            substituted = S_BOX[byte]

            new_row.append(substituted)

        new_state.append(new_row)

    return new_state

#======================================================================================
def shift_rows(state):
    new_state = []

    # Row 0 - no shift
    new_state.append(state[0])

    # Row 1 - shift left by 1
    row1 = state[1][1:] + state[1][:1]
    new_state.append(row1)

    # Row 2 - shift left by 2
    row2 = state[2][2:] + state[2][:2]
    new_state.append(row2)

    # Row 3 - shift left by 3
    row3 = state[3][3:] + state[3][:3]
    new_state.append(row3)

    return new_state

#======================================================================================
# helper for mix_columns
def mul_by_2(byte):
    # Multiply by {02} in GF(2^8)

    # Check if the leftmost bit is 1 before shifting
    left_bit_set = (byte & 0x80) != 0

    # Left shift by 1
    result = byte << 1

    # If overflow, reduce by XOR with 0x1b
    if left_bit_set:
        result = result ^ 0x1b

    # Keep only 8 bits
    return result & 0xff

#======================================================================================
# helper for mix_columns
def mul_by_3(byte):

    # Multiply by {03} in GF(2^8)
    return mul_by_2(byte) ^ byte

#======================================================================================
def mix_columns(state):
    new_state = []

    # Make a placeholder
    for row in range(4):
        new_state.append([0, 0, 0, 0])

    # Do each column separately 
    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        # from the texbook, 6.4
        new_state[0][col] = mul_by_2(s0) ^ mul_by_3(s1) ^ s2 ^ s3
        new_state[1][col] = s0 ^ mul_by_2(s1) ^ mul_by_3(s2) ^ s3
        new_state[2][col] = s0 ^ s1 ^ mul_by_2(s2) ^ mul_by_3(s3)
        new_state[3][col] = mul_by_3(s0) ^ s1 ^ s2 ^ mul_by_2(s3)

    return new_state

#======================================================================================
# main
def main():
    sorted_d_number = "D01959487D01960675D01960691"

    # Get the state
    plaintext_bits = text_to_bits(sorted_d_number)[:128]
    plaintext_bytes = bits_to_bytes(plaintext_bits)
    state = bytes_to_state(plaintext_bytes)

    print_state(state, "Initial State (Input)")


    # Key Expansion 
    w = KeyExpansion(key)
    round_keys = build_round_keys(w)


    # Round 0
    state = add_round_key(state, round_keys[0])
    print_state(state, "State after Round 0 (AddRoundKey)")

    # Rounds 1 to 9
    for round_num in range(1, 10):

        # SubBytes
        state = sub_bytes(state)

        # ShiftRows
        state = shift_rows(state)

        # MixColumns
        state = mix_columns(state)

        # AddRoundKey
        state = add_round_key(state, round_keys[round_num])

        label = "State after Round " + str(round_num)
        print_state(state, label)


    # Round 10
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    print_state(state, "State after Round 10 (Ciphertext)")


main()