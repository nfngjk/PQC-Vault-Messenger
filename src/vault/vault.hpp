#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace pqc {

    class Vault {

        public:

            static void keygen(const std::string& name);
            static void encrypt(const std::string& input_path, const std::string& output_path, const std::string& key_name);
            static void decrypt(const std::string& input_path, const std::string& output_path, const std::string& key_name);

        private:

            static std::vector<uint8_t> read_file(const std::string& path);
            static void write_file(const std::string& path, const std::vector<uint8_t>& data);

    };
    
}