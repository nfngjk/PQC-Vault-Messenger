#pragma once

#include <cstring>
#include <vector>
#include <stdexcept>
#include <cstdint>

namespace pqc {

    struct PqcFile {

        std::vector<uint8_t> kyber_public_key;
        std::vector<uint8_t> kyber_ciphertext;

        std::vector<uint8_t> init_vec;
        std::vector<uint8_t> auth_tag;
        std::vector<uint8_t> encrypted_data;

        std::vector<uint8_t> sig_public_key;
        std::vector<uint8_t> signature;

    };

    class PqcFormat {

        public:

            static std::vector<uint8_t> serialize(const PqcFile& file);
            static PqcFile deserialize(const std::vector<uint8_t>& data);

        private:

            static void write_u32(std::vector<uint8_t>& buffer, uint32_t value);
            static uint32_t read_u32(const uint8_t* pointer);

    };

}