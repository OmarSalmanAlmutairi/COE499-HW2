class AESKeyExpansion:
    # AES constants for key expansion
    RCON = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A
    ]

    # AES S-Box for the key expansion subroutine
    S_BOX = [
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
    ]

    def __init__(self, key):
        self.key = key
        self.key_size = len(key) * 8  # Convert byte length to bits
        self.n_rounds = self.get_number_of_rounds()
        self.round_keys = self.key_expansion()

    # Determine the number of rounds based on the key size
    def get_number_of_rounds(self):
        if self.key_size == 128:
            return 10
        elif self.key_size == 256:
            return 14
        else:
            raise ValueError("Unsupported key size. AES only supports 128-bit and 256-bit keys.")

    # Rotate word (left circular shift)
    @staticmethod
    def rotate(word):
        return word[1:] + word[:1]

    # Substitutes a word using the S-Box
    def sub_word(self, word):
        return [self.S_BOX[b] for b in word]

    # Key expansion function
    def key_expansion(self):
        expanded_keys = list(self.key)
        key_size = len(self.key)

        for i in range(key_size, 4 * (self.n_rounds + 1) * 4, 4):
            temp = expanded_keys[i - 4:i]
            if i % key_size == 0:
                temp = self.sub_word(self.rotate(temp))
                temp[0] ^= self.RCON[i // key_size - 1]
            elif key_size == 32 and i % key_size == 16:
                temp = self.sub_word(temp)
            expanded_keys += [x ^ y for x, y in zip(temp, expanded_keys[i - key_size:i - key_size + 4])]

        return self.get_round_keys(expanded_keys)

    # Convert the expanded keys into readable round keys
    def get_round_keys(self, expanded_keys):
        round_keys = []
        for i in range(self.n_rounds + 1):
            round_key = expanded_keys[i * 16:(i + 1) * 16]
            round_keys.append(round_key)
        return round_keys

    # Write AES key and round keys to a file
    def write_keys_to_file(self, filename='aes_keys.txt'):
        with open(filename, 'w') as f:
            f.write(f"AES Key: {''.join([f'{byte:02x}' for byte in self.key])}\n")
            f.write("AES Round Keys:\n")
            for i, round_key in enumerate(self.round_keys):
                f.write(f"Round {i}: {''.join([f'{byte:02x}' for byte in round_key])}\n")

    @staticmethod
    def convert_key_from_ascii_string(key_string):
        """
        Converts an ASCII string AES key into an array of integers (byte values).
        """
        if len(key_string) not in [16, 32]:
            raise ValueError("AES key must be a 16-character (128-bit) or 32-character (256-bit) ASCII string.")
        return [ord(char) for char in key_string]


# Example usage of the AESKeyExpansion class
def main():
    # Example AES key as an ASCII string (16 characters for AES-128 or 32 characters for AES-256)
    ascii_key_string = "ThisIsASecretKey"  # Example AES-128 key (16 chars) or "ThisIsASecretKeyOf32CharsLength!" for AES-256

    # Convert the ASCII string into an array of byte values
    key_array = AESKeyExpansion.convert_key_from_ascii_string(ascii_key_string)

    # Initialize the AES key expansion class with the converted key
    aes_expansion = AESKeyExpansion(key_array)

    # Write the keys to a file
    aes_expansion.write_keys_to_file()

    print(f"AES Key and round keys have been generated and saved to aes_keys.txt.")


if __name__ == "__main__":
    main()
