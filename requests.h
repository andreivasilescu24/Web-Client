#ifndef _REQUESTS_
#define _REQUESTS_

#include "nlohmann/json.hpp"
#include "nlohmann/json_fwd.hpp"

char *compute_get_request(char *host, char *url,
                            char *login_token, char* JWT);

char *compute_post_request(char *host, char *url, char* content_type, 
                            nlohmann::json message_content, char *login_token, char* JWT);

char* compute_delete_request(char* host, char* url, char* login_token, char* JWT);

#endif
