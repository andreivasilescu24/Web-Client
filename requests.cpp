#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include <string>

char *compute_get_request(char *host, char *url,
                            char *login_token, char *JWT)
{
    char *message = (char*) calloc(BUFLEN, sizeof(char));
    char *line = (char*) calloc(LINELEN, sizeof(char));

    // Step 1: write the method name, URL, request params (if any) and protocol type
    sprintf(line, "GET %s HTTP/1.1", url);

    compute_message(message, line);

    // Step 2: add the host
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    // sprintf(line, "Content-Type: %s", content_type);
    // compute_message(message, line);
    // Step 3 (optional): add headers and/or cookies, according to the protocol format
    if (login_token != NULL) {
        sprintf(line, "Cookie: %s", login_token);
        compute_message(message, line);
    }

    if(JWT != NULL) {
        sprintf(line, "Authorization: Bearer %s", JWT);
        compute_message(message, line);
    }
    // Step 4: add final new line
    compute_message(message, "");
    return message;
}

char *compute_post_request(char *host, char *url, char* content_type, nlohmann::json message_content, char **cookies, int cookies_count)
{
    char *message = (char*) calloc(BUFLEN, sizeof(char));
    char *line = (char*) calloc(LINELEN, sizeof(char));
    char *body_data_buffer = (char*) calloc(LINELEN, sizeof(char));

    // Step 1: write the method name, URL and protocol type
    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);

    sprintf(line, "Host: %s", host);
    compute_message(message, line);
    
    // Step 2: add the host
    /* Step 3: add necessary headers (Content-Type and Content-Length are mandatory)
            in order to write Content-Length you must first compute the message size
    */
    sprintf(line, "Content-Type: %s", content_type);
    compute_message(message, line);

    sprintf(line, "Content-Length: %d\n", message_content.dump().length());
    compute_message(message, line);
    // Step 4 (optional): add cookies
    if (cookies != NULL) {
       
    }
    // Step 5: add new line at end of header
    sprintf(body_data_buffer, "%s", message_content.dump().c_str());

    // Step 6: add the actual payload data
    memset(line, 0, LINELEN);
    compute_message(message, body_data_buffer);

    free(line);
    free(body_data_buffer);

    return message;
}
