#include "vault/vault.hpp"
#include <iostream>
#include <string>
#include "messenger/server.hpp"
#include "messenger/handshake.hpp"
#include "messenger/client.hpp"

void print_usage() {
    
    std::cout << R"(

        PQC_Project - Post-Quantum Cryptography Encryption Tool

        Usage:

        1. pqc_project keygen <name>
        2. pqc_project encrypt <input> <output.pqc> <keyname>
        3. pqc_project decrypt <input.pqc> <output.txt> <keyname>
        4. pqc_project listen <port>
        5. pqc_project client <host> <port>

    )";

}

int main(int argc, char* argv[]) {

    if(argc < 2) {

        print_usage();

        return 1;

    }

    std::string command = argv[1];

    try {

        if(command == "keygen") {

            if(argc != 3) {

                std::cerr << "Usage: pqc_project keygen <name>" << std::endl;

                return 1;

            }

            pqc::Vault::keygen(argv[2]);

        }

        else if(command == "encrypt") {

            if(argc != 5) {

                std::cerr << "Usage: pqc_project encrypt <input> <output.pqc> <keyname>" << std::endl;

                return 1;

            }

            pqc::Vault::encrypt(argv[2], argv[3], argv[4]);

        }

        else if(command == "decrypt") {

            if(argc != 5) {

                std::cerr << "Usage: pqc_project decrypt <input.pqc> <output.txt> <keyname>" << std::endl;

                return 1;

            }

            pqc::Vault::decrypt(argv[2], argv[3], argv[4]);

        }

        else if(command == "listen") {

            if(argc != 3) {

                std::cerr << "Usage: pqc_project listen <port>" << std::endl;

                return 1;

            }

            else {

                pqc::Server server(std::stoi(argv[2]));

                server.run();

            }

        }

        else if(command == "connect") {

            if(argc != 4) {

                std::cerr << "Usage: pqc_project client <host> <port>" << std::endl;

                return 1;

            }

            else {

                pqc::Client client(argv[2], std::stoi(argv[3]));

                client.run();
                
            }

        }

        else {

            std::cerr << "Unknown command: " << command << std::endl;

            print_usage();

            return 1;

        }

    }

    catch(const std::exception& ex) {

        std::cerr << "Error: " << ex.what() << std::endl;

        return 1;

    }

    return 0;

}