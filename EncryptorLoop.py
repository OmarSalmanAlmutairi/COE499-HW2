from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import time

# Set your 128-bit AES key here (replace with your actual key)
key = bytes.fromhex('00112233445566778899aabbccddeeff')  # Example key

# AES uses a 16-byte (128-bit) IV
iv = os.urandom(16)

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
    #time.sleep(1)
