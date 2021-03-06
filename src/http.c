/*
 * Handles transactions between web client and web server
 * Supports HTTP/1.1
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <jwt.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>

#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"

// Need macros here because of the sizeof
#define CRLF "\r\n"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

static const char * NEVER_EMBED_A_SECRET_IN_CODE = "supa secret2";

static bool verify(struct http_transaction *ta);
static bool confirmCredentials(struct http_transaction * ta);
static bool handle_fallback(struct http_transaction *ta, char *basedir, char * fallback);

/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2)      
    {
        return false;
    }

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
        return false;

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CRLF, &endptr);
    if (http_version == NULL)  // would be HTTP 0.9
        return false;

    if (!strcmp(http_version, "HTTP/1.1"))
        ta->req_version = HTTP_1_1;
    else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
        return false;

    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta)
{
    for (;;) {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF))       // empty CRLF
            return true;

        header[len-2] = '\0';
        /* Each header field consists of a name followed by a 
         * colon (":") and the field value. Field names are 
         * case-insensitive. The field value MAY be preceded by 
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        char *field_value = strtok_r(NULL, " \t", &endptr);    // skip leading & trailing OWS

        if (field_name == NULL)
            return false;

        if (!strcasecmp(field_name, "Content-Length")) {
            ta->req_content_len = atoi(field_value);
        }

        /* Handle other headers here. */
        if (!strcasecmp(field_name, "Cookie")) {
            char * ret;
            ret = strstr(field_value, "auth-token=");
            if (ret != NULL)
            {
                ta->signature = NULL;
                ret += 11;
                char * token;
                strtok_r(ret, ";", &token);
                ta->signature = ret;
            }
            else
            {
                ta->signature = NULL;
            }
            
        }
    }
}

const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void 
http_add_header(buffer_t * resp, char* key, char* fmt, ...)
{
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len)
{
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response 
 * to the response buffer.  Used in send_response_header */
static void
start_response(struct http_transaction * ta, buffer_t *res)
{
    buffer_appends(res, "HTTP/1.1 ");

    switch (ta->resp_status) {
    case HTTP_OK:
        buffer_appends(res, "200 OK");
        break;
    case HTTP_BAD_REQUEST:
        buffer_appends(res, "400 Bad Request");
        break;
    case HTTP_PERMISSION_DENIED:
        buffer_appends(res, "403 Permission Denied");
        break;
    case HTTP_NOT_FOUND:
        buffer_appends(res, "404 Not Found");
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        buffer_appends(res, "405 Method Not Allowed");
        break;
    case HTTP_REQUEST_TIMEOUT:
        buffer_appends(res, "408 Request Timeout");
        break;
    case HTTP_REQUEST_TOO_LONG:
        buffer_appends(res, "414 Request Too Long");
        break;
    case HTTP_NOT_IMPLEMENTED:
        buffer_appends(res, "501 Not Implemented");
        break;
    case HTTP_SERVICE_UNAVAILABLE:
        buffer_appends(res, "503 Service Unavailable");
        break;
    case HTTP_INTERNAL_ERROR:
    default:
        buffer_appends(res, "500 Internal Server Error");
        break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client */
static bool
send_response_header(struct http_transaction *ta)
{
    buffer_t response;
    buffer_init(&response, 80);

    start_response(ta, &response);
    if (bufio_sendbuffer(ta->client->bufio, &response) == -1)
        return false;

    buffer_appends(&ta->resp_headers, CRLF);
    if (bufio_sendbuffer(ta->client->bufio, &ta->resp_headers) == -1)
        return false;

    buffer_delete(&response);
    return true;
}

/* Send a full response to client with the content in resp_body. */
static bool
send_response(struct http_transaction *ta)
{
    add_content_length(&ta->resp_headers, ta->resp_body.len);

    if (!send_response_header(ta))
    {
        return false;
    }

    return bufio_sendbuffer(ta->client->bufio, &ta->resp_body) != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool
send_error(struct http_transaction * ta, enum http_response_status status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
    return send_response(ta);
}

/* Send Not Found response. */
static bool
send_not_found(struct http_transaction *ta)
{
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found", 
        bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world 
 * servers use more extensive lists such as /etc/mime.types
 */
static const char *
guess_mime_type(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";

    if (!strcasecmp(suffix, ".css"))
        return "text/css";
    return "text/plain";
}

/* Handle HTTP transaction for static files. */
static bool
handle_static_asset(struct http_transaction *ta, char *basedir)
{
    char fname[PATH_MAX];

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);

    if (access(fname, R_OK)) {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else
        {
            if (html5_fallback)
            {
                return handle_fallback(ta, basedir, "./index.html");
            }
        }
            return send_not_found(ta);
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1) {
        if (html5_fallback)
        {
            return handle_fallback(ta, basedir, "./index.html");
        }
        return send_not_found(ta);
    }

    ta->resp_status = HTTP_OK;
    add_content_length(&ta->resp_headers, st.st_size);
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    success = bufio_sendfile(ta->client->bufio, filefd, NULL, st.st_size) == st.st_size;
out:
    close(filefd);
    return success;
}

/* Handle HTTP fallback procedure */
static bool handle_fallback(struct http_transaction *ta, char *basedir, char * fallback)
{
    char * fname = fallback;

    if (access(fname, R_OK)) {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else
            return send_not_found(ta);
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1) {
        return send_not_found(ta);
    }

    ta->resp_status = HTTP_OK;
    add_content_length(&ta->resp_headers, st.st_size);
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    success = bufio_sendfile(ta->client->bufio, filefd, NULL, st.st_size) == st.st_size;
out:
    close(filefd);
    return success;
}

/* Handle HTTP GET & POST requests along with creating authentication tokens.*/
static int
handle_api(struct http_transaction *ta)
{
    if (ta->req_method == HTTP_POST)
    {
        if (!confirmCredentials(ta))
        {
            return send_error(ta, HTTP_PERMISSION_DENIED, "Authentication failed.");
        }
        else
        {
            jwt_t *mytoken;

            if (jwt_new(&mytoken))
                return send_error(ta, HTTP_INTERNAL_ERROR, "Token Creation Failed");

            if (jwt_add_grant(mytoken, "sub", "user0"))
                return send_error(ta, HTTP_INTERNAL_ERROR, "Token Creation Failed2");

            time_t now = time(NULL);
            if (jwt_add_grant_int(mytoken, "iat", now))
                return send_error(ta, HTTP_INTERNAL_ERROR, "Token Creation Failed3");

            if (jwt_add_grant_int(mytoken, "exp", now + token_expiration_time))
                return send_error(ta, HTTP_INTERNAL_ERROR, "Token Creation Failed4");

            if (jwt_set_alg(mytoken, JWT_ALG_HS256, 
                    (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, strlen(NEVER_EMBED_A_SECRET_IN_CODE)))
                return send_error(ta, HTTP_INTERNAL_ERROR, "Token Creation Failed5");

            char *encoded = jwt_encode_str(mytoken);
            if (encoded == NULL)
                return send_error(ta, HTTP_INTERNAL_ERROR, "Encoding Failed");

            ta->resp_status = HTTP_OK;

            char *grants = jwt_get_grants_json(mytoken, NULL); // NULL means all
            if (grants == NULL)
                return send_error(ta, HTTP_INTERNAL_ERROR, "Grant Return Failed");
            
            char newEncode[strlen(encoded) + 20];
            snprintf(newEncode, sizeof(newEncode), "auth-token=%s; Path=/", 
                    encoded);
            http_add_header(&ta->resp_headers, "Set-Cookie", newEncode);
            buffer_appends(&ta->resp_body, grants);
            send_response(ta);
        }
    }
    else if (ta->req_method == HTTP_GET)
    {
        ta->resp_status = HTTP_OK;
        if (!verify(ta))
        {
            buffer_appends(&ta->resp_body, "{}");
            send_response(ta);
        }  
        else
        {
            jwt_t * decoded;
            jwt_decode(&decoded, ta->signature, 
                (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, 
                strlen(NEVER_EMBED_A_SECRET_IN_CODE));
            char *grants = jwt_get_grants_json(decoded, NULL);
            buffer_appends(&ta->resp_body, grants);
            send_response(ta);
        }
    }
    else
    {
        return send_error(ta, HTTP_METHOD_NOT_ALLOWED, "METHOD NOT SUPPORTED");
    }    
    return 1;
}

/* Set up an http client, associating it with a bufio buffer. */
void 
http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
bool
http_handle_transaction(struct http_client *self)
{
    struct http_transaction ta;
    memset(&ta, 0, sizeof ta);
    ta.client = self;

    if (!http_parse_request(&ta))
        return false;

    if (!http_process_headers(&ta))
        return false;

    if (ta.req_content_len > 0) {
        int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
        if (rc != ta.req_content_len)
            return false;
    }

    buffer_init(&ta.resp_headers, 1024);
    http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server");
    buffer_init(&ta.resp_body, 0);

    bool rc = false;

    char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);
    if (strstr(req_path, "../") != NULL || strstr(req_path, "/..") != NULL) {
        return send_error(&ta, HTTP_NOT_FOUND, "404 NOT FOUND");
    }
    
    if (STARTS_WITH(req_path, "/api")) {
        if (strcmp(req_path, "/api/login") == 0)
            rc = handle_api(&ta);
        else
            return send_error(&ta, HTTP_NOT_FOUND, "404 NOT FOUND");
    } else if (STARTS_WITH(req_path, "/private")) {

        if (ta.req_method == HTTP_POST || ta.req_method == HTTP_UNKNOWN) 
        {
            return send_error(&ta, HTTP_METHOD_NOT_ALLOWED, "405 METHOD NOT SUPPORTED");
        }

        if (verify(&ta)) //authenticated
        {
            rc = handle_static_asset(&ta, server_root);
        }
        else
        {
            rc = send_error(&ta, HTTP_PERMISSION_DENIED, "403 Forbidden");
        }
    } else {
        rc = handle_static_asset(&ta, server_root);
    }

    buffer_delete(&ta.resp_headers);
    buffer_delete(&ta.resp_body);

    return rc && !(ta.req_version == HTTP_1_0);
}

/**
 * Keep client on the line and process transactions until connection closed
 * Basically check until handle transaction returns false
 */
bool
http_handle_client(struct http_client *self)
{
    while (http_handle_transaction(self))
    {
        
    }
    return true;
}

/**
 * Static method made to return a boolean as to whether or not a HTTP transaction was verifyed and if not
 * than it handles it appropriately.
 */
static bool verify(struct http_transaction *ta)
{
    jwt_t *decoded;
    
    if (ta->signature == NULL)
    {
        return false;
    }
    char * word = ta->signature;
    int result = jwt_decode(&decoded, word, 
            (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, strlen(NEVER_EMBED_A_SECRET_IN_CODE));
    if (result != 0)
    {
        return false;
    }
    else //sign passes, check claims
    {
        //iat > 0, < current time
        // exp > current
        // sub = user0
        char *grants = jwt_get_grants_json(decoded, NULL); // NULL means all
        if (grants == NULL)
            perror("jwt_get_grants_json"), exit(-1);

        //exp
        time_t now = time(NULL); //current time
        char * check;
        check = strstr(grants, "\"exp\":");
        if (check == NULL)
        {
            return false;
        }
        check += 6;
        strtok(check, ",");
        int issue = atoi(check);
        if (issue < (int) now)
        {
            return false;
        }

        //iat
        grants = jwt_get_grants_json(decoded, NULL);
        check = strstr(grants, "\"iat\":");
        if (check == NULL)
        {
            return false;
        }
        check += 6;
        strtok(check, ",");
        issue = atoi(check);
        if (issue > (int) now)
        {
            return false;
        }

        //sub
        grants = jwt_get_grants_json(decoded, NULL);
        check = strstr(grants, "\"sub\":\"");
        if (check == NULL)
        {
            return false;
        }
        check += 7;
        strtok(check, "\"");
        if (strcmp("user0", check) != 0)
        {
            return false;
        }
        return true;
    }
}

/**
 * Checks user credentials for proper user and pass
 */
static bool confirmCredentials(struct http_transaction * ta)
{
    char * entry = bufio_offset2ptr(ta->client->bufio, ta->req_body);
    char entry2[strlen(entry)+1];
    memcpy(entry2, entry, (strlen(entry)+1) * sizeof(char));
    
    //check JSON
    if (entry[0] != '{' && entry[strlen(entry)] != '}')
    {
        return false;
    }

    //isolate user
    char * user = strstr(entry, "\"username\"");
    if (user == NULL)
    {
        return false;
    }
    user += 10;
    while (*user != '\"' && *user != '\0')
    {
        user++;
    }
    if (*user == '\0')
    {
        return false;
    }
    user+=1; 
    char * martyr;
    strtok_r(user, "\"", &martyr);
    if (strcmp(user, "user0") != 0)
    {
        printf("user fail: %s\n", user);
        return false;
    }

    char * pass = strstr(entry2, "\"password\"");
    if (pass == NULL)
    {
        return false;
    }
    pass += 10;
    while (*pass != '\"' && *pass != '\0')
    {
        pass++;
    }
    if (*pass == '\0')
    {
        return false;
    }
    pass+=1; 
    char * martyr2;
    strtok_r(pass, "\"", &martyr2);
    if (strcmp(pass, "thepassword") != 0)
    {
        printf("password fail: %s\n", pass);
        return false;
    }
    return true;
}