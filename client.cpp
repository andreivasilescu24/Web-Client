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
#define JSON_CONTENT_TYPE "application/json"

#define REGISTER_PATH "/api/v1/tema/auth/register"
#define LOGIN_PATH "/api/v1/tema/auth/login"
#define ENTER_LIBRARY_PATH "/api/v1/tema/library/access"
#define GET_BOOKS_PATH "/api/v1/tema/library/books"


int main() {
    std::string input_command;
    char* login_cookie = NULL;
    char* JWT = NULL;

    while(getline(std::cin, input_command)) {
        int connection_socket = open_connection(IP_SERVER, PORT_SERVER, AF_INET, SOCK_STREAM, 0);

        if(!input_command.compare("register")) {
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
            send_to_server(connection_socket, post_request_message);
            char* server_response = receive_from_server(connection_socket);

            if(strstr(server_response, "201 Created") != NULL) {
                std::cout << std::endl << "User registered successfully!" << std::endl << std::endl;
            } else {
                nlohmann::json server_json_response = nlohmann::json::parse(strchr(server_response, '{'));
                std::string error_response = server_json_response["error"];

                error_response = error_response.substr(0, error_response.length());

                std::cout << std::endl << error_response << std::endl << std::endl;
            }

            close_connection(connection_socket);

        } else if(!input_command.compare("login")) {
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
            send_to_server(connection_socket, post_login_message);
            char* server_response = receive_from_server(connection_socket);

            
            if(strstr(server_response, "200 OK") != NULL) {
                std::cout << std::endl << "User logged in successfully!" << std::endl << std::endl;

                char* cookie_start = strstr(server_response, "connect.sid");
                char* received_login_cookie = strtok(cookie_start, ";");
                
                if(!login_cookie) {
                    login_cookie = new char[100];
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

            close_connection(connection_socket);
        
        } else if(!input_command.compare("enter_library")) {
            if(login_cookie) {
                if(!JWT) {
                    char* enter_library_request_message = compute_get_request(IP_SERVER, ENTER_LIBRARY_PATH, login_cookie, NULL);
                    send_to_server(connection_socket, enter_library_request_message);
                    char* server_response = receive_from_server(connection_socket);

                    if(strstr(server_response, "200 OK")) {
                        std::cout << std::endl << "You've gained access to the library!" << std::endl << std::endl;

                        nlohmann::json server_json_response = nlohmann::json::parse(strchr(server_response, '{'));
                        std::string JWT_token = server_json_response["token"];

                        JWT_token = JWT_token.substr(0, JWT_token.length());

                        if(JWT) {
                            strcpy(JWT, (char*) JWT_token.c_str());
                        } else {
                            JWT = new char[1000];
                            strcpy(JWT, (char*) JWT_token.c_str());
                        }

                    } else {
                        nlohmann::json server_json_response = nlohmann::json::parse(strchr(server_response, '{'));
                        std::string error_response = server_json_response["error"];

                        error_response = error_response.substr(0, error_response.length());

                        std::cout << std::endl << error_response << std::endl << std::endl;
                    }

    
                } else {
                    std::cout << std::endl << "Access has already been granted to the current user!" << std::endl << std::endl;
                }

            } else {
                std::cout << std::endl << "You have to be logged in to gain access to the library!" << std::endl << std::endl;
            }

            close_connection(connection_socket);

        } else if(!input_command.compare("get_books")) {
            if(!JWT) {
                std::cout << "\nYou need acces to the library first!\n\n";
            } else {
                char* get_books_request_message = compute_get_request(IP_SERVER, GET_BOOKS_PATH, NULL, JWT);
                send_to_server(connection_socket, get_books_request_message);
                char* server_response = receive_from_server(connection_socket);
                std::cout << server_response;
            }
        
            close_connection(connection_socket);
        
        } else if(!input_command.compare("exit")) {
            close_connection(connection_socket);
            delete[] JWT;
            delete[] login_cookie;
            break;
        }

    }


    return 0;
}