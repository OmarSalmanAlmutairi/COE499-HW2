#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

// Function to convert a hex string to a byte array
std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Function to read a file into a byte array
std::vector<unsigned char> read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open file " + filename);
    }
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)),
                                       std::istreambuf_iterator<char>());
}

// Function to write a byte array to a file
void write_file(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not write to file " + filename);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// Function to encrypt the data using AES-256 CBC
std::vector<unsigned char> encrypt_aes256(const std::vector<unsigned char>& data, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    std::vector<unsigned char> ciphertext(data.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;

    // Encrypt the data
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), data.size());
    ciphertext_len += len;

    // Finalize encryption
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

int main() {
    // Hardcoded AES-256 key in hexadecimal (64 hex digits -> 32 bytes)
    std::string hex_key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"; // Example key
    std::vector<unsigned char> key = hex_to_bytes(hex_key);

    if (key.size() != 32) {
        std::cerr << "Error: AES-256 requires a 256-bit key (32 bytes)" << std::endl;
        return 1;
    }

    // Generate a 16-byte IV (AES block size is 128 bits or 16 bytes)
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        std::cerr << "Error: Could not generate IV" << std::endl;
        return 1;
    }

    try {
        // Read the two BMP files
        std::vector<unsigned char> bmp1 = read_file("image1.bmp");
        std::vector<unsigned char> bmp2 = read_file("image2.bmp");

        // Encrypt the first BMP file
        std::vector<unsigned char> encrypted_bmp1 = encrypt_aes256(bmp1, key.data(), iv);

        // Encrypt the second BMP file
        std::vector<unsigned char> encrypted_bmp2 = encrypt_aes256(bmp2, key.data(), iv);

        // Write the encrypted files back to disk
        write_file("encrypted_image1.bmp.enc", encrypted_bmp1);
        write_file("encrypted_image2.bmp.enc", encrypted_bmp2);

        // Print key and IV for reference
        std::cout << "AES-256 Key (hex): " << hex_key << std::endl;
        std::cout << "IV (hex): ";
        for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)iv[i];
        }
        std::cout << std::endl;

        std::cout << "Encryption completed successfully!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
