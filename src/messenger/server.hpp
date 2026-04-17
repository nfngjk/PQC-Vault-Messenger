#pragma once

#include <vector>
#include <string>
#include "handshake.hpp"

namespace pqc {

    class Server {

        public:

            explicit Server(int port);

            ~Server();


            void run();

        private:

            int port_;
            int server_socket_;

            void handle_client(int client_socket);

            static void send_encrypted_message(int socket, const std::vector<uint8_t>& key, const std::string& message);
            static std::string receive_encrypted_message(int socket, const std::vector<uint8_t>& key);
            static void send_raw_message(int socket, const std::vector<uint8_t>& data);
            static std::vector<uint8_t> receive_raw_message(int socket);

    };

}