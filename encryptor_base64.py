from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

class AESImageEncryptor:
    def __init__(self, base64_key):
        # Decode the base64 key and determine the key length
        self.key = self.decode_base64_key(base64_key)
        self.key_size = len(self.key) * 8  # Key size in bits

        # Check if the key is AES-128 (16 bytes) or AES-256 (32 bytes)
        if self.key_size == 128:
            print("AES-128 key provided")
        elif self.key_size == 256:
            print("AES-256 key provided")
        else:
            raise ValueError("Invalid key size. Must be either 128-bit (16 bytes) or 256-bit (32 bytes).")

    @staticmethod
    def decode_base64_key(base64_key):
        """
        Decodes the Base64-encoded key and returns the raw binary key.
        """
        decoded_key = base64.b64decode(base64_key)
        key_length = len(decoded_key)
        if key_length not in [16, 32]:
            raise ValueError("Key must be either 128-bit (16 bytes) or 256-bit (32 bytes).")
        return decoded_key

    def encrypt_images(self, image_files, output_file):
        """
        Encrypts the provided list of images and writes the encrypted output to a single file in an infinite loop.
        """
        while True:
            # AES uses a 16-byte (128-bit) IV (Initialization Vector)
            iv = os.urandom(16)
    
            # Create the cipher object with the appropriate AES key size (AES-128 or AES-256)
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
    
            encrypted_data = b''
    
            # Encrypt each image file
            for image_file in image_files:
                with open(image_file, 'rb') as f:
                    data = f.read()
    
                    # Pad data to be a multiple of the block size (16 bytes for AES)
                    padding_length = 16 - (len(data) % 16)
                    data += bytes([padding_length] * padding_length)
    
                    # Encrypt the padded data
                    encrypted_data += encryptor.update(data)
    
            # Finalize the encryption for the last block
            encrypted_data += encryptor.finalize()
    
            # Write the IV and encrypted data to the output file
            with open(output_file, 'wb') as f:
                f.write(iv + encrypted_data)
    
            print(f"Encryption complete. Encrypted data saved to {output_file}.")

# Example usage
def main():
    # Base64 encoded AES-128 or AES-256 key
    base64_key = "sI7p6arwdHc0CeVnr48gxMOIiK5HkUNMUz2TT6tR++k="  # Example AES-256 key
    
    # Initialize the AESImageEncryptor class
    encryptor = AESImageEncryptor(base64_key)

    # List of image files to encrypt (add your actual image file paths here)
    image_files = ['image1.bmp', 'image2.bmp']

    # Encrypt the images and write to the output file
    encryptor.encrypt_images(image_files, 'encrypted_images.bin')

if __name__ == "__main__":
    main()
