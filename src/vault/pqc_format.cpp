#include "pqc_format.hpp"
#include <cstring>

namespace pqc {

    static const uint8_t MAGIC[4] = {'P', 'Q', 'C', '\0'};
    static const uint8_t VERSION = 0x01;

    void PqcFormat::write_u32(std::vector<uint8_t>& buffer, uint32_t value) {

        buffer.push_back((value >> 24) & 0xFF);
        buffer.push_back((value >> 16) & 0xFF);
        buffer.push_back((value >> 8) & 0xFF);
        buffer.push_back(value & 0xFF);

    }

    uint32_t PqcFormat::read_u32(const uint8_t* pointer) {

        return (static_cast<uint32_t>(pointer[0]) << 24) | (static_cast<uint32_t>(pointer[1]) << 16) | (static_cast<uint32_t>(pointer[2]) << 8) | static_cast<uint32_t>(pointer[3]);

    }

    std::vector<uint8_t> PqcFormat::serialize(const PqcFile& file) {

        std::vector<uint8_t> buffer;

        buffer.insert(buffer.end(), MAGIC, MAGIC + 4);
        buffer.push_back(VERSION);
        buffer.push_back(0x00);
        buffer.push_back(0x01);

        write_u32(buffer, file.kyber_public_key.size());
        buffer.insert(buffer.end(), file.kyber_public_key.begin(), file.kyber_public_key.end());

        write_u32(buffer, file.kyber_ciphertext.size());
        buffer.insert(buffer.end(), file.kyber_ciphertext.begin(), file.kyber_ciphertext.end());


        buffer.insert(buffer.end(), file.init_vec.begin(), file.init_vec.end());
        buffer.insert(buffer.end(), file.auth_tag.begin(), file.auth_tag.end());

        write_u32(buffer, file.encrypted_data.size());
        buffer.insert(buffer.end(), file.encrypted_data.begin(), file.encrypted_data.end());


        write_u32(buffer, file.sig_public_key.size());
        buffer.insert(buffer.end(), file.sig_public_key.begin(), file.sig_public_key.end());
        write_u32(buffer, file.signature.size());
        buffer.insert(buffer.end(), file.signature.begin(), file.signature.end());

        return buffer;

    }

    PqcFile PqcFormat::deserialize(const std::vector<uint8_t>& data) {

        const uint8_t* pointer = data.data();
        const uint8_t* end = pointer + data.size();

        if(data.size() < 7 || memcmp(pointer, MAGIC, 4) != 0) {

            throw std::runtime_error("Invalid file format: Missing magic number");

        }

        pointer = pointer + 4;

        uint8_t version = *pointer++;

        if(version != VERSION) {

            throw std::runtime_error("Unsupported file version");

        }

        pointer = pointer + 2;

        PqcFile file;

        auto read_field = [&](std::vector<uint8_t>& field) {

            if(pointer + 4 > end) {

                throw std::runtime_error("Unexpected end of data while reading field length");

            }

            uint32_t length = read_u32(pointer);
          
            pointer += 4;

            if(pointer + length > end) {

                throw std::runtime_error("Unexpected end of data while reading field data");

            }

            field.insert(field.end(), pointer, pointer + length);
          
            pointer += length;

        };

        auto read_fixed_field = [&](std::vector<uint8_t>& field, size_t expected_length) {

            if(pointer + expected_length > end) {

                throw std::runtime_error("Unexpected end of data while reading fixed-length field");

            }

            field.insert(field.end(), pointer, pointer + expected_length);
          
            pointer += expected_length;

        };

        read_field(file.kyber_public_key);
        read_field(file.kyber_ciphertext);
        
        read_fixed_field(file.init_vec, 12);
        read_fixed_field(file.auth_tag, 16);
        read_field(file.encrypted_data);

        read_field(file.sig_public_key);
        read_field(file.signature);

        return file;

    }


}