#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <vector>
#include <cstring>

// Function to decode Base64 to binary
std::vector<unsigned char> base64_decode(const std::string &base64_key) {
    BIO *bio, *b64;
    int decodeLen = (int)((base64_key.size() * 3) / 4); // Estimate the length of the decoded data
    std::vector<unsigned char> decoded_key(decodeLen);

    bio = BIO_new_mem_buf(base64_key.data(), -1);  // Create a memory buffer with the Base64 string
    b64 = BIO_new(BIO_f_base64());  // Create a Base64 BIO
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // Do not use newlines to flush the buffer
    bio = BIO_push(b64, bio);

    // Decode the Base64 key into the decoded_key vector
    int decoded_size = BIO_read(bio, decoded_key.data(), base64_key.size());
    decoded_key.resize(decoded_size);  // Resize vector to actual decoded size

    BIO_free_all(bio);
    return decoded_key;
}

// Function to print bytes in hexadecimal format
void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// AES-256 CBC encryption function
void encrypt_aes256(const std::vector<unsigned char>& plaintext, const unsigned char* key, unsigned char* iv, std::vector<unsigned char>& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    int len;
    int ciphertext_len;
    std::vector<unsigned char> buffer(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    // Perform encryption
    EVP_EncryptUpdate(ctx, buffer.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;

    // Finalize encryption
    EVP_EncryptFinal_ex(ctx, buffer.data() + len, &len);
    ciphertext_len += len;

    // Copy ciphertext to the output vector
    ciphertext.assign(buffer.begin(), buffer.begin() + ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    // Hardcoded AES-256 key in Base64
    std::string base64_key = "sI7p6arwdHc0CeVnr48gxMOIiK5HkUNMUz2TT6tR++k=";

    // Decode the Base64-encoded key
    std::vector<unsigned char> key = base64_decode(base64_key);

    // Check if the key is 32 bytes (256 bits) for AES-256
    if (key.size() != 32) {
        std::cerr << "Decoded key is not 32 bytes (AES-256 requires a 256-bit key)." << std::endl;
        return 1;
    }

    // Generate a 128-bit IV
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    // Example plaintext
    std::vector<unsigned char> plaintext = { 'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 't', 'e', 's', 't', '!' };

    std::vector<unsigned char> ciphertext;

    // Print key and IV for reference
    std::cout << "Key (in hex): ";
    print_hex(key.data(), key.size());

    std::cout << "IV (in hex): ";
    print_hex(iv, sizeof(iv));

    // Perform AES-256 encryption
    encrypt_aes256(plaintext, key.data(), iv, ciphertext);

    // Print the encrypted data (ciphertext)
    std::cout << "Ciphertext: ";
    print_hex(ciphertext.data(), ciphertext.size());

    // Keep the process alive to ensure keys remain in memory (for memory dump purposes)
    std::cout << "Encryption complete. Press Ctrl+C to exit.\n";
    while (true); // Infinite loop to keep keys in memory

    return 0;
}
