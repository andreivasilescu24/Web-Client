#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "helpers.h"
#include "requests.h"
#include "buffer.h"

#include "nlohmann/json.hpp"
#include "nlohmann/json_fwd.hpp"


#define IP_SERVER "34.254.242.81"
#define PORT_SERVER 8080
#define REGISTER_PATH "/api/v1/tema/auth/register"
#define JSON_CONTENT_TYPE "application/json"

int main() {
    std::string input_commannd;

    while(getline(std::cin, input_commannd)) {
        if(!input_commannd.compare("register")) {
            int conection_socket = open_connection(IP_SERVER, PORT_SERVER, AF_INET, SOCK_STREAM, 0);

            nlohmann::json to_send_message_register = nlohmann::json::object();

            std::string username;
            std::string password;
            
            std::cout << "username=";
            getline(std::cin, username);

            std::cout << "password=";
            getline(std::cin, password);

            to_send_message_register["username"] = username;
            to_send_message_register["password"] = password;

            char* post_request_message = compute_post_request(IP_SERVER, REGISTER_PATH, JSON_CONTENT_TYPE, to_send_message_register, NULL, 0);
            send_to_server(conection_socket, post_request_message);
            char* server_response = receive_from_server(conection_socket);
            std::cout << server_response;

        } else if(!input_commannd.compare("exit")) {
            break;
        }





    }


    return 0;
}