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
#define BOOKS_PATH "/api/v1/tema/library/books"

bool validate_id(std::string book_id) {
    if(book_id.length() == 0) {
        std::cout << std::endl << "The ID field is empty!" << std::endl << std::endl;
        return false;
    }

    for(char character : book_id) {
        if(!std::isdigit(character)) {
            std::cout << std::endl << "The entered ID should be a valid number!" << std::endl << std::endl;
            return false;
        }
    }

    return true;
}

bool validate_page_count(std::string page_count) {
    if(page_count.length() == 0) {
        std::cout << std::endl << "The \"page_count\" field is empty!" << std::endl << std::endl;
        return false;
    }

    for(char character : page_count) {
        if(!std::isdigit(character)) {
            std::cout << std::endl << "Page count should be a valid number!" << std::endl << std::endl;
            return false;
        }
    }

    return true;
}


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
                std::cout << std::endl << "Invalid username! (Username can't contain space characters)" << std::endl << std::endl;
                close_connection(connection_socket);
                continue;
            } else if(username.length() == 0) {
                std::cout << std::endl << "Invalid username! (Username field is empty)" << std::endl << std::endl;
                close_connection(connection_socket);
                continue;
            }

            std::cout << "password=";
            getline(std::cin, password);


            if(password.find(' ') != std::string::npos) {
                std::cout << std::endl << "Invalid password! (Password can't contain space characters)" << std::endl << std::endl;
                close_connection(connection_socket);
                continue;
            } else if(password.length() == 0) {
                std::cout << std::endl << "Invalid password! (Password field is empty)" << std::endl << std::endl;
                close_connection(connection_socket);
                continue;
            }

            to_send_message_register["username"] = username;
            to_send_message_register["password"] = password;

            char* post_request_message = compute_post_request(IP_SERVER, REGISTER_PATH, JSON_CONTENT_TYPE, to_send_message_register, login_cookie, JWT);
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
            if(login_cookie) {
                std::cout << std::endl << "Another user is already logged in! (Try logging out first)" << std::endl << std::endl;
            } else {
                nlohmann::json to_send_message_login = nlohmann::json::object();

                std::string username;
                std::string password;
                
                std::cout << "username=";
                getline(std::cin, username);

                if(username.find(' ') != std::string::npos) {
                    std::cout << std::endl << "Invalid username! (Username can't contain space characters)" << std::endl << std::endl;
                    close_connection(connection_socket);
                    continue;
                } else if(username.length() == 0) {
                    std::cout << std::endl << "Invalid username! (Username field is empty)" << std::endl << std::endl;;
                    close_connection(connection_socket);
                    continue;
                }

                std::cout << "password=";
                getline(std::cin, password);

                if(password.find(' ') != std::string::npos) {
                    std::cout << std::endl << "Invalid password! (Password can't contain space characters)" << std::endl << std::endl;
                    close_connection(connection_socket);
                    continue;
                } else if(password.length() == 0) {
                    std::cout << std::endl << "Invalid password! (Password field is empty)" << std::endl << std::endl;
                    close_connection(connection_socket);
                    continue;
                }

                to_send_message_login["username"] = username;
                to_send_message_login["password"] = password;

                char* post_login_message = compute_post_request(IP_SERVER, LOGIN_PATH, JSON_CONTENT_TYPE, to_send_message_login, login_cookie, JWT);
                send_to_server(connection_socket, post_login_message);
                char* server_response = receive_from_server(connection_socket);

                
                if(strstr(server_response, "200 OK") != NULL) {
                    std::cout << std::endl << "Welcome!" << std::endl << std::endl;

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
                std::cout << "\nYou need access to the library first!\n\n";
            } else {
                char* get_books_request_message = compute_get_request(IP_SERVER, BOOKS_PATH, login_cookie, JWT);
                send_to_server(connection_socket, get_books_request_message);
                char* server_response = receive_from_server(connection_socket);
                
                nlohmann::json books_array = nlohmann::json::parse(strchr(server_response, '['));
                
                for(nlohmann::json book : books_array) {
                    std::string book_title = book["title"];
                    std::cout << std::endl << "title= " << book_title.c_str() << std::endl;
                    std::cout << "id= " << book["id"] << std::endl;
                }
                std::cout << std::endl;

            }
        
            close_connection(connection_socket);
        
        } else if(!input_command.compare("get_book")) {
            if(!JWT) {
                std::cout << "\nYou need access to the library first!\n\n";
            } else {
                std::cout << "id=";
                
                std::string book_id;
                getline(std::cin, book_id);

                if(!validate_id(book_id)) {
                    close_connection(connection_socket);
                    continue;
                } else {
                    char* searched_id_path = new char[100];
                    strcpy(searched_id_path, BOOKS_PATH);
                    strcat(searched_id_path, "/");
                    strcat(searched_id_path, book_id.c_str());

                    char* get_book_request_message = compute_get_request(IP_SERVER, searched_id_path, login_cookie, JWT);
                    send_to_server(connection_socket, get_book_request_message);
                    char* server_response = receive_from_server(connection_socket);

                    nlohmann::json get_book_json = nlohmann::json::parse(strchr(server_response, '{'));

                    if(strstr(server_response, "200 OK")) {
                        std::cout << std::endl << "title=" << get_book_json["title"] << std::endl;
                        std::cout << "author=" << get_book_json["author"] << std::endl;
                        std::cout << "genre=" << get_book_json["genre"] << std::endl;
                        std::cout << "publisher=" << get_book_json["publisher"] << std::endl;
                        std::cout << "page_count=" << get_book_json["page_count"] << std::endl << std::endl;
                    } else if(strstr(server_response, "404 Not Found")) {
                        std::cout << std::endl << "Book with id=" << book_id << " doesn't exist!" << std::endl << std::endl;
                    } else {
                        std::string error_response = get_book_json["error"];
                        error_response = error_response.substr(0, error_response.length());

                        std::cout << std::endl << error_response << std::endl << std::endl;
                    }

                    delete[] searched_id_path;
                }

            }

            close_connection(connection_socket);
        } else if(!input_command.compare("add_book")) {
            if(!JWT) {
                std::cout << "\nYou need access to the library first!\n\n";
            } else {
                nlohmann::json to_send_message_add_book = nlohmann::json::object();

                std::string title, author, genre, publisher, page_count;

                std::cout << std::endl << "title=";
                getline(std::cin, title);
                to_send_message_add_book["title"] = title;

                std::cout << "author=";;
                getline(std::cin, author);
                to_send_message_add_book["author"] = author;

                std::cout << "genre=";
                getline(std::cin, genre);
                to_send_message_add_book["genre"] = genre;

                std::cout << "publisher=";
                getline(std::cin, publisher);
                to_send_message_add_book["publisher"] = publisher;

                std::cout << "page_count=";
                getline(std::cin, page_count);

                if(validate_page_count(page_count)) {
                    int number_page_count = std::stoi(page_count);
                    to_send_message_add_book["page_count"] = number_page_count;
                } else {
                    close_connection(connection_socket);
                    continue;
                }

                char* add_book_request_message = compute_post_request(IP_SERVER, BOOKS_PATH, JSON_CONTENT_TYPE, to_send_message_add_book, login_cookie, JWT);
                send_to_server(connection_socket, add_book_request_message);
                char* server_response = receive_from_server(connection_socket);
                
                if(strstr(server_response, "200 OK")) {
                    std::cout << std::endl << "Book was successfully added to your library!" << std::endl << std::endl;
                } else {
                    nlohmann::json add_book_json = nlohmann::json::parse(strchr(server_response, '{'));

                    std::string error_response = add_book_json["error"];
                    error_response = error_response.substr(0, error_response.length());

                    std::cout << std::endl << error_response << std::endl << std::endl;
                }
                
            }

            close_connection(connection_socket);
        } else if(!input_command.compare("delete_book")) {
            if(!JWT) {
                std::cout << "\nYou need access to the library first!\n\n";
            } else {
                std::cout << "id=";
                
                std::string book_id;
                getline(std::cin, book_id);

                if(!validate_id(book_id)) {
                    close_connection(connection_socket);
                    continue;
                } else {
                    char* delete_id_path = new char[100];
                    strcpy(delete_id_path, BOOKS_PATH);
                    strcat(delete_id_path, "/");
                    strcat(delete_id_path, book_id.c_str());

                    char* delete_book_request_message = compute_delete_request(IP_SERVER, delete_id_path, login_cookie, JWT);
                    send_to_server(connection_socket, delete_book_request_message);
                    char* server_response = receive_from_server(connection_socket);

                    if(strstr(server_response, "200 OK")) {
                        std::cout << std::endl << "Book with id=" << book_id << " was successfully deleted from your library!" << std::endl << std::endl;
                    } else if(strstr(server_response, "404 Not Found")) {
                        std::cout << std::endl << "Couldn't delete book with id=" << book_id << "! " << "(This book doesn't exist)" << std::endl << std::endl;
                    } else {
                        nlohmann::json add_book_json = nlohmann::json::parse(strchr(server_response, '{'));

                        std::string error_response = add_book_json["error"];
                        error_response = error_response.substr(0, error_response.length());

                        std::cout << std::endl << error_response << std::endl << std::endl;
                    }
                    

                    delete[] delete_id_path;
                }

            }

            close_connection(connection_socket);

        } else if(!input_command.compare("logout")) {
            if(!login_cookie) {
                std::cout << std::endl << "Logging out unnecessary! (No user is logged in)" << std::endl << std::endl;
            } else {
                delete[] JWT;
                delete[] login_cookie;
                JWT = NULL;
                login_cookie = NULL;

                std::cout << std::endl << "See you later!" << std::endl << std::endl;
            }
            close_connection(connection_socket);
        } else if(!input_command.compare("exit")) {
            delete[] JWT;
            delete[] login_cookie;
            close_connection(connection_socket);
            break;
        } else {
            std::cout << std::endl << "Invalid command" << std::endl << std::endl;
            close_connection(connection_socket);
        }

    }


    return 0;
}