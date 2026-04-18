#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "handshake.hpp"

namespace pqc {

    class Client {

        public:

            explicit Client(const std::string& host, int port);

            ~Client();

            void run();

        private:

            std::string host_;

            int port_;
            int socket_forward_;

            static void send_encrypt_message(int forward, const std::vector<uint8_t>& key, const std::string& message);
            static std::string receive_encrypted_message(int forward, const std::vector<uint8_t>& key);
           
            static void send_raw_message(int forward, const std::vector<uint8_t>& data);
            static std::vector<uint8_t> receive_raw_message(int forward);

    };

}