#ifndef HTTP_CONNECTOR_H
#define HTTP_CONNECTOR_H

#ifdef _WIN32
  #include <winsock2.h>
  #include <windows.h>
  #include <ws2ipdef.h>
  #include <ws2tcpip.h>
#else
  #include <sys/fcntl.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
#endif

#if defined(__GNU__)
  #include <unistd.h>
#elif defined(_MSC_VER)
  #include <io.h>
  #define ssize_t long
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/err.h>
#include <openssl/ssl3.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443

#define BUF_SIZE 10485760 // 10.48576MB

#define MAX_HTTP_HEADER_SIZE 16384

#define FREE(v) \
  do {          \
    free(v);\
    v = NULL;\
  } while(0);

#define INIT_ARRAY(type, size) (type*)calloc(size, sizeof(type))

typedef enum {
  GET,
  POST
} Method;

typedef enum {
  HTTP_1_1
} HttpVersion;

typedef enum {
  SUCCESS,
  FAI_MEM_ALLOC,
  DATA_IS_NULL,
  DATA_IS_LESS,
  NOT_FOUND_BODY,
  SIZE_OVER,
  UN_SUPPORT_SOCKET_FAMILIY,
  FAI_SET_IP_ADDR,
  FAI_SET_RES_DATA,
} LibHttpConnectorError;

typedef enum {
  Ipv4,
  Ipv6
} IpVersion;

typedef enum {
  TCP,
  UDP,
} PROTOCOL_FOR_SOCKET;

typedef struct SocketDataStruct {

  struct sockaddr_in target;
  
  int os_type;

  int is_ssl;
  SSL_CTX *ssl_ctx;
  SSL *ssl;

  #ifdef _WIN32
    SOCKET socket;
  #else
    int socket;
  #endif

} socket_data_s;

typedef struct UrlDataStruct {
  char *url;
  ssize_t url_size;
  
  char *hostname;
  ssize_t hostname_size;
  
  char *path_name;
  ssize_t path_name_size;

  char *body;
  ssize_t body_size;
  
  int protocol;
} url_data_s;

typedef struct ResponseStruct
{
  char *raw_header;
  char **header_list;
  char *body;
  ssize_t raw_header_size;
  ssize_t body_size;
  ssize_t header_list_size;
} response_s;


typedef struct IppAddrStringStruct
{
  size_t str_size;
  char *ipaddr_str;
} ipaddr_s;

typedef struct SockAddrStruct
{
  IpVersion ip_version;
  struct sockaddr_in for_ipv4;
  struct sockaddr_in6 for_ipv6;
} sock_addr_s;

LibHttpConnectorError set_http_response_data(const char *response_data, ssize_t size, response_s *result);

LibHttpConnectorError get_ipaddr_str_from_addrinfo(struct addrinfo *addr_info, ipaddr_s *dst);

int get_addr_info_from_hostname(const char* hostname, const char *service, struct addrinfo *hints, struct addrinfo **addr_info);

void init_socket(socket_data_s *socket_data, int af, int socktype);

LibHttpConnectorError set_addr_from_hostname(socket_data_s *socket_data, int af, int socktype, const char *service, const url_data_s *url_data);

int do_connect(socket_data_s *socket_data, int protocol, int is_ssl);
LibHttpConnectorError send_data_and_revice_response(socket_data_s *socket_data, const char *data, response_s *response);

int set_url_data(const char *url, ssize_t url_size, const char *data, ssize_t data_size, Method method, url_data_s *url_data);

char* create_header(url_data_s *url_data, const char* user_agent, Method method, HttpVersion version);

int get_http_response(const char *url, int af, PROTOCOL_FOR_SOCKET protocol, const char *user_agent, response_s *response);

void close_socket(socket_data_s *socket_data);

#endif
