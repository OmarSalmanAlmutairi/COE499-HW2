from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Helper function to convert an ASCII key to bytes
def convert_key_from_ascii_string(key_string):
    """
    Converts an ASCII string AES key into a byte array.
    The key must be either 16 characters (for AES-128) or 32 characters (for AES-256).
    """
    if len(key_string) == 16:
        return key_string.encode()  # 16 characters for AES-128
    elif len(key_string) == 32:
        return key_string.encode()  # 32 characters for AES-256
    else:
        raise ValueError("Key must be either 16 characters (128-bit) or 32 characters (256-bit) long.")

# Replace these keys with your actual AES key strings
ascii_key_string = "ThisIsASecretKey"  # Example AES-128 key (16 chars)
# ascii_key_string = "ThisIsASecretKeyOf32CharsLength!"  # Example AES-256 key (32 chars)

# Convert the ASCII key to bytes
key = convert_key_from_ascii_string(ascii_key_string)

# AES requires a 16-byte (128-bit) IV, generated anew for each encryption cycle
iv = os.urandom(16)

# List of image files to encrypt
image_files = ['image1.bmp', 'image2.bmp']  # Add your actual image file paths here

# Infinite loop to keep encrypting
while True:
    # Regenerate the IV and cipher for each encryption cycle to ensure security
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = b''

    # Encrypt each image
    for image_file in image_files:
        with open(image_file, 'rb') as f:
            data = f.read()

            # Pad the data to block size (16 bytes for AES)
            padding_length = 16 - (len(data) % 16)
            data += bytes([padding_length] * padding_length)

            # Encrypt the padded data
            encrypted_data += encryptor.update(data)

    # Finalize the encryption
    encrypted_data += encryptor.finalize()

    # Write the IV and encrypted data to a file (IV + encrypted data)
    with open('encrypted_images.bin', 'wb') as f:
        f.write(iv + encrypted_data)

    # Print a message to indicate that an encryption cycle is complete
    print("Encryption complete. Continuing...")

    # To minimize CPU usage, a delay could be removed. If necessary, adjust the delay time
    # Comment out the next line to remove the delay
    # time.sleep(1)
