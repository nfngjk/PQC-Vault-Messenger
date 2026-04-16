#include "vault.hpp"
#include "pqc_format.hpp"
#include "core/kyber.hpp"
#include "core/aes_gcm.hpp"
#include "core/dilithium.hpp"

#include <fstream>
#include <iostream>
#include <stdexcept>

namespace pqc {

    std::vector<uint8_t> Vault::read_file(const std::string& path) {

        std::ifstream file(path, std::ios::binary);

        if(!file) {

            throw std:: runtime_error("Failed to open file for reading: " + path);

        }

        return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());

    }

    void Vault::write_file(const std::string& path, const std::vector<uint8_t>& data) {

        std::ofstream file(path, std::ios::binary);

        if(!file) {

            throw std:: runtime_error("Failed to open file for writing: " + path);

        }

        file.write(reinterpret_cast<const char*>(data.data()), data.size());

    }

    void Vault::keygen(const std::string& name) {

        Kyber kyber;

        auto kyber_kp = kyber.keygen();

        write_file(name + "_kyber_public.key", kyber_kp.public_key);
        write_file(name + "_kyber_private.key", kyber_kp.private_key);

        Dilithium dilithium;

        auto dilithium_kp = dilithium.keygen();

        write_file(name + "_dilithium_public.key", dilithium_kp.public_key);
        write_file(name + "_dilithium_private.key", dilithium_kp.private_key);

        std::cout << "Keys generated and saved with base name: " << name << std::endl;
        std::cout << " " << name << "_kyber_public.key" << std::endl;
        std::cout << " " << name << "_dilithium_public.key" << std::endl;
        
    }

    void Vault::encrypt(const std::string& input_path, const std::string& output_path, const std::string& key_name) {

        auto plaintext = read_file(input_path);

        std::cout << "Read plaintext from: " << input_path << std::endl;

        auto kyber_public_key = read_file(key_name + "_kyber_public.key");
        auto dilithium_private_key = read_file(key_name + "_dilithium_private.key");
        auto dilithium_public_key = read_file(key_name + "_dilithium_public.key");

        Kyber kyber;

        auto encaps_result = kyber.encapsulate(kyber_public_key);

        std::vector<uint8_t> aes_key(encaps_result.shared_private.begin(), encaps_result.shared_private.begin() + 32);

        auto encrypted_data = AesGcm::encrypt(plaintext, aes_key);

        PqcFile pqc_file;

        pqc_file.kyber_public_key = kyber_public_key;
        pqc_file.kyber_ciphertext = encaps_result.ciphertext;
        pqc_file.init_vec = encrypted_data.init_vec;
        pqc_file.auth_tag = encrypted_data.auth_tag;
        pqc_file.encrypted_data = encrypted_data.ciphertext;
        pqc_file.sig_public_key = dilithium_public_key;

        std::vector<uint8_t> data_to_sign;

        data_to_sign.insert(data_to_sign.end(), pqc_file.kyber_ciphertext.begin(), pqc_file.kyber_ciphertext.end());
        data_to_sign.insert(data_to_sign.end(), pqc_file.init_vec.begin(), pqc_file.init_vec.end());
        data_to_sign.insert(data_to_sign.end(), pqc_file.auth_tag.begin(), pqc_file.auth_tag.end());
        data_to_sign.insert(data_to_sign.end(), pqc_file.encrypted_data.begin(), pqc_file.encrypted_data.end());

        Dilithium dilithium;

        pqc_file.signature = dilithium.sign(data_to_sign, dilithium_private_key);

        auto serialized_data = PqcFormat::serialize(pqc_file);

        write_file(output_path, serialized_data);
        
        std::cout << "File encrypted and saved to: " << output_path << std::endl;
        
    }

    void Vault::decrypt(const std::string& input_path, const std::string& output_path, const std::string& key_name) {

        auto raw = read_file(input_path);
        
        PqcFile pqc_file = PqcFormat::deserialize(raw);

        auto kyber_secret_key = read_file(key_name + "_kyber_private.key");

        std::vector<uint8_t> data_to_verify;

        data_to_verify.insert(data_to_verify.end(), pqc_file.kyber_ciphertext.begin(), pqc_file.kyber_ciphertext.end());
        data_to_verify.insert(data_to_verify.end(), pqc_file.init_vec.begin(), pqc_file.init_vec.end());
        data_to_verify.insert(data_to_verify.end(), pqc_file.auth_tag.begin(), pqc_file.auth_tag.end());
        data_to_verify.insert(data_to_verify.end(), pqc_file.encrypted_data.begin(), pqc_file.encrypted_data.end());

        Dilithium dilithium;

        if(!dilithium.verify(data_to_verify, pqc_file.signature, pqc_file.sig_public_key)) {

            throw std::runtime_error("Signature verification failed. The file may have been tampered with.");

        }

        std::cout << "Signature verified successfully." << std::endl;

        Kyber kyber;

        auto shared_secret = kyber.decapsulate(pqc_file.kyber_ciphertext, kyber_secret_key);

        std::vector<uint8_t> aes_key(shared_secret.begin(), shared_secret.begin() + 32);

        auto plaintext = AesGcm::decrypt(pqc_file.encrypted_data, aes_key, pqc_file.init_vec, pqc_file.auth_tag);

        write_file(output_path, plaintext);

        std::cout << "File decrypted and saved to: " << output_path << std::endl;

    }
    
}