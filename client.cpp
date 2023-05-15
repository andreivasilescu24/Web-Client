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
#define LOGIN_PATH "/api/v1/tema/auth/login"
#define JSON_CONTENT_TYPE "application/json"

int main() {
    std::string input_commannd;
    char* login_cookie = NULL;

    while(getline(std::cin, input_commannd)) {
        if(!input_commannd.compare("register")) {
            int conection_socket = open_connection(IP_SERVER, PORT_SERVER, AF_INET, SOCK_STREAM, 0);

            nlohmann::json to_send_message_register = nlohmann::json::object();

            std::string username;
            std::string password;
            
            std::cout << "username=";
            getline(std::cin, username);

            if(username.find(' ') != std::string::npos) {
                std::cout << "Invalid username! (Username can't contain space characters)" << std::endl;
                continue;
            } else if(username.length() == 0) {
                std::cout << "Invalid username! (Username field is empty)" << std::endl;
                continue;
            }

            std::cout << "password=";
            getline(std::cin, password);


            if(password.find(' ') != std::string::npos) {
                std::cout << "Invalid password! (Password can't contain space characters)" << std::endl;
                continue;
            } else if(password.length() == 0) {
                std::cout << "Invalid password! (Password field is empty)" << std::endl;
                continue;
            }

            to_send_message_register["username"] = username;
            to_send_message_register["password"] = password;

            char* post_request_message = compute_post_request(IP_SERVER, REGISTER_PATH, JSON_CONTENT_TYPE, to_send_message_register, NULL, 0);
            send_to_server(conection_socket, post_request_message);
            char* server_response = receive_from_server(conection_socket);

            if(strstr(server_response, "201 Created") != NULL) {
                std::cout << std::endl << "User registered successfully!" << std::endl << std::endl;
            } else {
                nlohmann::json server_json_response = nlohmann::json::parse(strchr(server_response, '{'));
                std::string error_response = server_json_response["error"];

                error_response = error_response.substr(0, error_response.length());

                std::cout << std::endl << error_response << std::endl << std::endl;
            }

            close_connection(conection_socket);

        } else if(!input_commannd.compare("login")) {
            int conection_socket = open_connection(IP_SERVER, PORT_SERVER, AF_INET, SOCK_STREAM, 0);

            nlohmann::json to_send_message_login = nlohmann::json::object();

            std::string username;
            std::string password;
            
            std::cout << "username=";
            getline(std::cin, username);

            if(username.find(' ') != std::string::npos) {
                std::cout << "Invalid username! (Username can't contain space characters)" << std::endl;
                continue;
            } else if(username.length() == 0) {
                std::cout << "Invalid username! (Username field is empty)" << std::endl;
                continue;
            }

            std::cout << "password=";
            getline(std::cin, password);

            if(password.find(' ') != std::string::npos) {
                std::cout << "Invalid password! (Password can't contain space characters)" << std::endl;
                continue;
            } else if(password.length() == 0) {
                std::cout << "Invalid password! (Password field is empty)" << std::endl;
                continue;
            }

            to_send_message_login["username"] = username;
            to_send_message_login["password"] = password;

            char* post_login_message = compute_post_request(IP_SERVER, LOGIN_PATH, JSON_CONTENT_TYPE, to_send_message_login, NULL, 0);
            send_to_server(conection_socket, post_login_message);
            char* server_response = receive_from_server(conection_socket);

            
            if(strstr(server_response, "200 OK") != NULL) {
                std::cout << std::endl << "User logged in successfully!" << std::endl << std::endl;

                char* cookie_start = strstr(server_response, "connect.sid");
                char* received_login_cookie = strtok(cookie_start, ";");
                
                if(!login_cookie) {
                    login_cookie = (char*) malloc(100 * sizeof(char));
                    strcpy(login_cookie, received_login_cookie);
                } else {
                    std::cout << std::endl << "Another user is already logged in! (Try logging out first)" << std::endl << std::endl;
                }

            } else {
                nlohmann::json server_json_response = nlohmann::json::parse(strchr(server_response, '{'));
                std::string error_response = server_json_response["error"];

                error_response = error_response.substr(0, error_response.length());

                std::cout << std::endl << error_response << std::endl << std::endl;
            }

            close_connection(conection_socket);
        
        } else if(!input_commannd.compare("exit")) {
            break;
        }





    }


    return 0;
}