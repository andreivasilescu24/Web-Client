#ifndef _REQUESTS_
#define _REQUESTS_

#include "nlohmann/json.hpp"
#include "nlohmann/json_fwd.hpp"

// computes and returns a GET request string (query_params
// and cookies can be set to NULL if not needed)
char *compute_get_request(char *host, char *url,
                            char *cookies, char* JWT);

// computes and returns a POST request string (cookies can be NULL if not needed)
char *compute_post_request(char *host, char *url, char* content_type, nlohmann::json message_content, char **cookies, int cookies_count);

#endif
