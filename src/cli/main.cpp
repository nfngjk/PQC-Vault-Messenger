extern "C" {

    #include <oqs/oqs.h>

}

#include <iostream>
#include <fstream>
#include <iomanip>
#include "core/kyber.hpp"
#include "core/dilithium.hpp"
#include "core/aes_gcm.hpp"
#include "vault/vault.hpp"

void print_hex(const std::string& label, const std::vector<uint8_t>& data, size_t n = 16) {

    std::cout << label << ": ";

    for(size_t i = 0; i < n && i < data.size(); i++) {

        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]) << " ";
    
    }

    std::cout << "...(" << std::dec << data.size() << " bytes)" << std::endl;

}

int main() {

    std::cout << "kyber test..." << std::endl;

    try {
    
        pqc::Kyber kyber;

        auto kp = kyber.keygen();

        print_hex("Public Key", kp.public_key);
        print_hex("Private Key", kp.private_key);

        auto encap = kyber.encapsulate(kp.public_key);
        
        print_hex("Encapsulated Key", encap.ciphertext);
        print_hex("Shared Private Key (Encaps)", encap.shared_private);

        auto shared_private = kyber.decapsulate(encap.ciphertext, kp.private_key);

        print_hex("Shared Private Key (Decaps)", shared_private);

        if(shared_private == encap.shared_private) {

            std::cout << "Shared keys match!" << std::endl;

        } 
        
        else {

            std::cout << "Shared keys do NOT match!" << std::endl;

        }

    }

    catch(const std::exception& ex) {

        std::cerr << "Error: " << ex.what() << std::endl;

        return 1;

    }

    std::cout << std::endl;

    std::cout << "dilithium test..." << std::endl;
 
    try {

        pqc::Dilithium dilithium;

        auto kp = dilithium.keygen();

        print_hex("Public Key", kp.public_key);
        print_hex("Private Key", kp.private_key);

        std::string message = "hey...";
        std::vector<uint8_t> messages(message.begin(), message.end());

        auto signature = dilithium.sign(messages, kp.private_key);

        print_hex("Signature", signature);

        bool ok = dilithium.verify(messages, signature, kp.public_key);

        std::cout << "Signature verification: " << (ok ? "SUCCESS" : "FAILURE") << std::endl;

        messages[0] = message[0] ^ 0xFF;

        bool check = dilithium.verify(messages, signature, kp.public_key);

        std::cout << "Signature verification with modified message: " << (check ? "SUCCESS" : "FAILURE") << std::endl;

    }

    catch(const std::exception& ex) {

        std::cerr << "Error: " << ex.what() << std::endl;

        return 1;

    }

    std::cout << std::endl;
    
    std::cout << "AES-GCM test..." << std::endl;

    try {

        std::vector<uint8_t> key(32, 0xAB);
        
        std::string str = "Hey...";

        std::vector<uint8_t> plaintext(str.begin(), str.end());

        auto encrypted = pqc::AesGcm::encrypt(plaintext, key);

        print_hex("Ciphertext", encrypted.ciphertext);
        print_hex("Initialization Vector", encrypted.init_vec);
        print_hex("Authentication Tag", encrypted.auth_tag);

        auto decrypted = pqc::AesGcm::decrypt(encrypted.ciphertext, key, encrypted.init_vec, encrypted.auth_tag);

        std::string result = std::string(decrypted.begin(), decrypted.end());

        std::cout << "Decrypted plaintext: " << result << std::endl;
        std::cout << "Decryption " << (result == str ? "SUCCESS" : "FAILURE") << std::endl;

    }

    catch(const std::exception& ex) {

        std::cerr << "Error: " << ex.what() << std::endl;

        return 1;

    }

    std::cout << std::endl;
    
    std::cout << "Vault test..." << std::endl;

    try {

        pqc::Vault::keygen("testkey");
        
        {

            std::ofstream in_file("test.txt");

            in_file << "This is a test file for encryption." << std::endl;
            in_file << "It contains multiple lines of text." << std::endl;
            
        }

        pqc::Vault::encrypt("test.txt", "test_output.pqc", "testkey");
        pqc::Vault::decrypt("test_output.pqc", "test_decrypted.txt", "testkey");

        std::ifstream file("test_decrypted.txt");

        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        std::cout << "Decrypted file content: " << content << std::endl;

    }

    catch(const std::exception& ex) {

        std::cerr << "Error: " << ex.what() << std::endl;

        return 1;

    }

    return 0;

}