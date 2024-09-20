from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import time

# Set your 128-bit AES key here (replace with your actual key)
key = bytes.fromhex('00112233445566778899aabbccddeeff')  # Example key

# AES uses a 16-byte (128-bit) IV
iv = os.urandom(16)

# AES constants for key expansion
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
]

# AES S-Box for the key expansion subroutine
S_BOX = [
    # S-Box table
]

# Function to perform key expansion for AES-128 (manual key schedule)
def aes_key_expansion(key):
    round_keys = [list(key[i:i+4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = round_keys[i-1]
        if i % 4 == 0:
            # Rotate temp bytes and apply S-box substitution
            temp = [S_BOX[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= RCON[i // 4 - 1]
        round_keys.append([round_keys[i-4][j] ^ temp[j] for j in range(4)])
    return [b''.join(bytes([b]) for b in word) for word in round_keys]

# Write AES key and round keys to a file
def write_key_and_round_keys_to_file(key, round_keys, filename='aes_keys.txt'):
    with open(filename, 'w') as f:
        f.write(f"AES Key: {key.hex()}\n")
        f.write("AES Round Keys:\n")
        for i in range(0, len(round_keys), 4):
            f.write(f"Round {i//4}: {round_keys[i].hex()}\n")

# Generate AES round keys
round_keys = aes_key_expansion(key)

# Write AES key and round keys to the file
write_key_and_round_keys_to_file(key, round_keys)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

# List of image files to encrypt (add your images here)
image_files = ['image1.bmp', 'image2.bmp']  # Add the paths to your images

# Infinite loop to keep encrypting
while True:
    encryptor = cipher.encryptor()  # Create a new encryptor for each loop
    encrypted_data = b''

    # Encrypt each image
    for image_file in image_files:
        with open(image_file, 'rb') as f:
            data = f.read()

            # Pad data to block size (16 bytes for AES)
            padding_length = 16 - (len(data) % 16)
            data += bytes([padding_length] * padding_length)

            # Encrypt the padded data
            encrypted_data += encryptor.update(data)

    # Finalize the encryption for the last block
    encrypted_data += encryptor.finalize()

    # Write the encrypted data to a single file
    with open('encrypted_images.bin', 'wb') as f:
        f.write(iv + encrypted_data)

    # Optional: Print a message to indicate an encryption cycle is complete
    print("Encryption complete. Sleeping for 1 second...")

    # Sleep for 1 second to prevent high CPU usage (adjust as needed)
    time.sleep(1)
