#include "./http_connector.h"
#include <stdlib.h>

LibHttpConnectorError get_content_length_from_raw_header(const char *header, ssize_t size, long *length) {
  const char *regex_pattern = "Content-Length: ([0-9]+)";
  regex_t regex_buf;

  if (regcomp(&regex_buf, regex_pattern, REG_EXTENDED | REG_NEWLINE) != 0) {
    return FAI_COMP_REGEX;
  }

  regmatch_t matches[3];
  int matches_size = sizeof(matches) / sizeof(regmatch_t);
  if (regexec(&regex_buf, header, matches_size, matches, 0) != 0) {
    return NOT_MATCHES_PATTERN;
  }

  for (int i = 1; i < matches_size; ++i) {
    int start = matches[i].rm_so;
    int end = matches[i].rm_eo;
    if (start == -1 || end == -1) {
      continue;
    }

    int size = (end - start);
    char *num_str = INIT_ARRAY(char, size + 1);
    memmove(num_str, header + start, size);

    long result = strtol(num_str, NULL, 10);
    *length = result;
  }

  return SUCCESS;
}

LibHttpConnectorError get_http_header_from_response(const char *response_data, ssize_t size, response_s *res) {
  if(response_data == NULL) {
    printf("Error: response data is NULL\n");
    return DATA_IS_NULL;
  }

  if(size < 1) {
    printf("Error: size is less than one.\n");
    return DATA_IS_LESS;
  }

  char *header = INIT_ARRAY(char, size + 1);
  ssize_t count = 0;
  int new_line_count = 0;
  char previous = 0;
  for(ssize_t i = 0; i < size; ++i) {

    if(previous == '\n' && response_data[i] != '\r') {
      new_line_count = 0;
      previous = 0;
    }

    if(previous == '\r') {
      if(response_data[i] == '\n') {
        ++new_line_count;
        previous = '\n';
      } else {
        new_line_count = 0;
        previous = 0;
      }
    }

    if(response_data[i] == '\r') {
      previous = '\r';
    }

    header[i] = response_data[i];
    
    ++count;

    if(new_line_count == 2)
      break;
    
  }

  if(count > MAX_HTTP_HEADER_SIZE) {
    FREE(header);

    printf("Error: over max http header size. Limit size: %d bytes\n", MAX_HTTP_HEADER_SIZE);
    
    return SIZE_OVER;
  }

  header[count] = '\0';

  char *reallocated = realloc(header, count + 1);
  if(reallocated == NULL) {
    FREE(header);

    printf("Error: failed reallocate at header\n");

    return FAI_MEM_ALLOC;
  }

  header = reallocated;
  res->raw_header = header;
  res->raw_header_size = count;
  
  return SUCCESS;
}

LibHttpConnectorError set_http_response_data(const char *response_data, ssize_t size, response_s *result)
{
  if(response_data == NULL) {
    printf("Error: response data is NULL\n");
    return DATA_IS_NULL;
  }

  if(size < 1) {
    printf("Error: size is less than one.\n");
    return DATA_IS_LESS;
  }

  if (result == NULL) {
    return BUF_IS_NULL;
  }

  int err = 0;
  if (result->header_list_size == 0) {
    err = get_http_header_from_response(response_data, size, result);
    if (err != SUCCESS) {
      return FAI_GET_HTTP_HEADER;
    }
  }

  int count = result->raw_header_size;
  if(count >= size) {
    printf("Error: missing body\n");
    return NOT_FOUND_BODY;
  }

  char *body = INIT_ARRAY(char, size + 1);
  ssize_t body_pos = 0;
  for(ssize_t i = count; i < size; ++i) {
    body[body_pos] = response_data[i];
    ++body_pos;
  }
  body[body_pos] = '\0';

  result->body_size = body_pos + 1;
  result->body = body;

  
  return SUCCESS;
}

LibHttpConnectorError get_ipaddr_str_from_addrinfo(struct addrinfo *addr_info, ipaddr_s *dst)
{
  size_t str_size = 0;
  switch (addr_info->ai_family) {
  case AF_INET:
    str_size = INET_ADDRSTRLEN;
    break;
  case AF_INET6:
    str_size = INET6_ADDRSTRLEN;
    break;
  default:
    return UN_SUPPORT_SOCKET_FAMILIY;
  }

  dst->ipaddr_str = INIT_ARRAY(char, str_size);
  if (dst->ipaddr_str == NULL) {
    return FAI_MEM_ALLOC;
  }
  
  char *buf = INIT_ARRAY(char, str_size);
  if (buf == NULL) {
    return FAI_MEM_ALLOC;
  }

  if (addr_info->ai_family == AF_INET) {
    struct in_addr *addr = &((struct sockaddr_in *)addr_info->ai_addr)->sin_addr;
    const char *pointer = inet_ntop(addr_info->ai_family, addr, buf, str_size);
    memmove(dst->ipaddr_str, buf, str_size);
  }

  if (addr_info->ai_family == AF_INET6) {
    struct in6_addr *addr = &((struct sockaddr_in6 *)addr_info->ai_addr)->sin6_addr;
    const char *pointer = inet_ntop(addr_info->ai_family, addr, buf, str_size);
    memmove(dst->ipaddr_str, buf, str_size);
  }

  size_t str_length = strlen(dst->ipaddr_str);
  dst->str_size = str_length;

  return SUCCESS;
}


int get_addr_info_from_hostname(const char* hostname, const char *service, struct addrinfo *hints, struct addrinfo **addr_info)
{
  int err = 0;
  err = getaddrinfo(hostname, service, hints, addr_info);
  if (err != 0) {
    int code = 0;
    #ifdef _WIN32
    code = WSAGetLastError();
    #else
    code = errno;
    #endif

    printf("getaddrinfo error from err (%d) : %s\n", err, gai_strerror(err));
    printf("getaddrinfo error (%d) : %s\n", code, gai_strerror(code));
  }

  return err;
}

void init_socket(socket_data_s *socket_data, int af, int socktype)
{
  #ifdef _WIN32
    SOCKET sock = socket(af, socktype, 0);
  #else
    int sock = socket(af, socktype, 0);
  #endif

  struct sockaddr_in target;
  target.sin_family = af;

  socket_data->socket = sock;
  socket_data->target = target;
}

LibHttpConnectorError set_addr_from_hostname(socket_data_s *socket_data, int af, int socktype, int protocol, const char *service, const url_data_s *url_data)
{
  struct addrinfo *addr_info = malloc(sizeof(struct addrinfo));
  struct addrinfo hints;
  hints.ai_family = af;
  hints.ai_socktype = socktype;
  hints.ai_flags = AI_PASSIVE;

  switch (protocol) {
  case TCP:
    hints.ai_protocol = IPPROTO_TCP;
    break;
  case UDP:
    hints.ai_protocol = IPPROTO_UDP;
    break;
  }
  
  int err = get_addr_info_from_hostname(url_data->hostname, service, &hints, &addr_info);
  if (err == -1) {
    freeaddrinfo(addr_info);
    return FAI_SET_HOSTNAME;
  }

  ipaddr_s ipaddr;  
  err = get_ipaddr_str_from_addrinfo(addr_info, &ipaddr);
  if (err != SUCCESS) {
    freeaddrinfo(addr_info);

    return err;
  }

  char* addr = "127.0.0.1";

  if(ipaddr.ipaddr_str != NULL)
    addr = ipaddr.ipaddr_str;

  err = inet_pton(addr_info->ai_family, addr, &socket_data->target.sin_addr.s_addr);
  freeaddrinfo(addr_info);
  if (!err) {
    return FAI_SET_IP_ADDR;
  }

  return SUCCESS;
}

LibHttpConnectorError send_data_and_revice_response(socket_data_s *socket_data, const char *data, response_s *response)
{
  char *buf = INIT_ARRAY(char, BUF_SIZE);
  if (buf == NULL) {
    return FAI_MEM_ALLOC;
  }

  long readed_size = 0;
  int err = 0;
  SSL *ssl = socket_data->ssl;
  int is_ssl = socket_data->is_ssl;
  if(!is_ssl)
    err = send(socket_data->socket, data, strlen(data), 0);
  else
    err = SSL_write(ssl, data, strlen(data));

  struct timeval tv;
  tv.tv_sec = 10;
  tv.tv_usec = 0;
  
  fd_set readfds, fds;
  FD_ZERO(&readfds);
  FD_SET(socket_data->socket, &readfds);
  
  int count = 0;
  char *result = NULL;
  long result_size = 1;
  long content_length = -1;
  do{
    memcpy(&fds, &readfds, sizeof(fd_set));

    // first argument is must be that socket + 1. This value is max size of socket.
    err = select(socket_data->socket + 1, &fds, NULL, NULL, &tv);
    if(!err) {
      /* printf("timeout\n"); */
      goto end;
    }

    if(FD_ISSET(socket_data->socket, &fds)) {

      memset(buf, 0, BUF_SIZE);
      
      if(!is_ssl)
        readed_size = recv(socket_data->socket, buf, BUF_SIZE, 0);
      else
        readed_size = SSL_read(ssl, buf, BUF_SIZE);

      /* printf("count: %d, readed size: %ld\nbody: %s\n", count, readed_size, buf); */
    }

    result_size += readed_size;
    if(result == NULL) {
      result = INIT_ARRAY(char, result_size);
      strncpy(result, buf, readed_size);
    } else {
      char *check_realloc = realloc(result, result_size);
      if(check_realloc != NULL) {
        result = check_realloc;
        strncat(result, buf, readed_size);
      }
    }

    ++count;

    if (response->raw_header_size <= 0) {
      err = get_http_header_from_response(result, strlen(result), response);
      if (err == SUCCESS) {
        err = get_content_length_from_raw_header(response->raw_header, response->raw_header_size, &content_length);
      }
    }

    if ((result_size - response->raw_header_size) >= content_length) {
      break;
    }

  } while(readed_size > 0 && count < 3);

  // result_size is 1 meaning is terminating string length
  if (result_size == 1) {
    result_size = 0;
  }

 end:
  if(is_ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(socket_data->ssl_ctx);
    ERR_free_strings();
  }

  close_socket(socket_data);

  FREE(buf);

  if(set_http_response_data(result, strlen(result), response) != SUCCESS) {
    /* if (response->raw_header_size > 0) { */
    /*   FREE(response->raw_header); */
    /*   response->raw_header_size = 0; */
    /* } */
    
    FREE(result);
    return FAI_SET_RES_DATA;
    /* printf("header size: %ld\nheader: %s\n\nbody size: %ld\nbody: %s\n", */
    /*        response->raw_header_size, */
    /*        response->raw_header, */
    /*        response->body_size, */
    /*        response->body); */
  }
  
  FREE(result);  

  return SUCCESS;
}

LibHttpConnectorError do_connect(socket_data_s *socket_data, int protocol, int is_ssl)
{
  if(protocol == HTTP_PORT) {
    socket_data->target.sin_port = htons(HTTP_PORT);
  } else if (protocol == HTTPS_PORT) {
    socket_data->target.sin_port = htons(HTTPS_PORT);
  } else {
    return UNKNOWN_PROTOCOL;
  }

  int err = 0;

  err = connect(socket_data->socket, (struct sockaddr *)&socket_data->target, sizeof(socket_data->target));
  if (err == -1) {
    printf("do_connect error: %s\n", strerror(errno));
    return CONNECT_ERROR;
  }

  
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;

  if (is_ssl) {
    SSL_load_error_strings();
    SSL_library_init();

    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    ssl = SSL_new(ctx);

    err = SSL_set_fd(ssl, socket_data->socket);
    if(err == 0) {
      printf("SSL_set_fd error\n");
      
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      
      return ERROR_SSL_SET_FD;
    }

    err = SSL_connect(ssl);
    if(err == 0) {
      printf("SSL_connect error\n");
      
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      
      return ERROR_SSL_CONNECT;
    }
  }

  socket_data->is_ssl = is_ssl;
  socket_data->ssl = ssl;
  socket_data->ssl_ctx = ctx;


  return SUCCESS;
}

void close_socket(socket_data_s *socket_data) {
#ifdef _WIN32
  closesocket(socket_data->socket);
#else
  close(socket_data->socket);
#endif
}

int set_url_data(const char *url, ssize_t url_size, const char *data, ssize_t data_size, Method method, url_data_s *url_data)
{

  if(url == NULL) {
    puts("Error: url is NULL");
    return -1;
  }
  
  if(url_size < 7) {
    puts("Error: invalid url. Please least length 7 or higher.");
    return -1;
  }

  char check_protocol[8];
  for(int i = 0; i < 7; ++i) {
    check_protocol[i] = url[i];
  }
  check_protocol[7] = '\0';

  int is_valid_protocol = 0;
  int protocol = 0;

  printf("cmp: %s\n", check_protocol);
  if(strcmp(check_protocol, "http://") == 0) {
    is_valid_protocol = 1;
    protocol = HTTP_PORT;
  } else if(strcmp(check_protocol, "https:/") == 0) {
    is_valid_protocol = 1;
    protocol = HTTPS_PORT;
  }

  if(!is_valid_protocol) {
    puts("Error: unknown protocol\n");
    return -1;
  }

  char *hostname = INIT_ARRAY(char, url_size + 1);

  int init_value = 7;
  if(protocol == HTTPS_PORT)
    init_value = 8;

  ssize_t pos = 0;
  for(ssize_t i = (ssize_t)init_value; i < url_size; ++i) {
    if(url[i] == '/')
      break;

    hostname[pos] = url[i];
    ++pos;
  }
  hostname[pos] = '\0';

  ssize_t path_pos = 0;
  char *path = INIT_ARRAY(char, url_size + 1);
  for(ssize_t i = pos + init_value; i < url_size; ++i) {
    path[path_pos] = url[i];
    ++path_pos;
  }
  
  if(path_pos == 0) {
    ++path_pos;
    path[0] = '/';
  } else {
    path[path_pos] = '\0';
  }

  char *body = NULL;
  url_data->body = NULL;
  if(method == POST && data != NULL) {
    body = INIT_ARRAY(char, data_size + 1);

    strncpy(body, data, data_size);
    body[data_size] = '\0';
  }


  url_data->hostname = hostname;
  url_data->hostname_size = (ssize_t)(pos + 1);

  url_data->path_name = path;
  url_data->path_name_size = (ssize_t)(path_pos + 1);

  if(body != NULL) {
    url_data->body = body;
    url_data->body_size = data_size;
  }
  
  url_data->url = INIT_ARRAY(char, url_size);
  url_data->url_size = url_size;
  strncpy(url_data->url, url, url_size);

  url_data->protocol = protocol;

  return 1;
}

char* create_header(url_data_s *url_data, const char *user_agent, Method method, HttpVersion version)
{

  char *method_string = INIT_ARRAY(char, 4);
  if(method == GET)
    strncpy(method_string, "GET", 3);
  else if(method == POST)
    strncpy(method_string, "POST", 4);
  else {
    FREE(method_string);

    printf("unknown method!\n");

    return NULL;
  }

  char *http_version_string = INIT_ARRAY(char, 8);
  if(version == HTTP_1_1) {
    const char *http_1_1 = "HTTP/1.1";
    strncpy(http_version_string, http_1_1, strlen(http_1_1));
  } else {
    FREE(method_string);
    FREE(http_version_string);
    
    printf("invalid version!\n");

    return NULL;
  }

  const char *host_prefix = "Host: ";
  const char *header_end_line = "\r\n";
  const char *user_agent_prefix = "User-Agent: ";

  ssize_t size = strlen(method_string) +
    url_data->path_name_size +
    strlen(http_version_string) +
    (strlen(header_end_line) * 2) + // first and end line length
    2;

  if(user_agent != NULL)
    size += strlen(user_agent) + strlen(user_agent_prefix) + strlen(header_end_line);

  if(url_data->hostname != NULL)
    size += strlen(host_prefix) + url_data->hostname_size + strlen(header_end_line);
  else {
    printf("Error: hostname is empty!\n");

    FREE(method_string);
    FREE(http_version_string);
    
    return NULL;
  }
  
  char *header = INIT_ARRAY(char, size + 1);
  if(user_agent != NULL)
    sprintf(header, "%s %s %s\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", method_string, url_data->path_name, http_version_string, url_data->hostname, user_agent);
  else
    sprintf(header, "%s %s %s\r\nHost: %s\r\n\r\n", method_string, url_data->path_name, http_version_string, url_data->hostname);

  FREE(method_string);
  FREE(http_version_string);

  return header;
}

LibHttpConnectorError get_http_response(const char *url, int af, PROTOCOL_FOR_SOCKET protocol, const char *user_agent, response_s *response)
{
  url_data_s *url_data = (url_data_s*)malloc(sizeof(url_data_s));
  int err = set_url_data(url, strlen(url), NULL, 0, GET, url_data);
  if(err == -1) {
    FREE(url_data);
    puts("Error: failed set_url_data in get_http_response\n");
    return FAI_SET_URL_DATA;
  }

  int is_ssl = 0;
  int protocol_for_http = url_data->protocol;
  char *service = "http";
  if (protocol_for_http == HTTPS_PORT) {
    service = "https";
    is_ssl = 1;
  }
  printf("service: %s\n", service);

  int socktype = 0;
  switch (protocol) {
  case TCP:
    socktype = SOCK_STREAM;
    break;
  case UDP:
    socktype = SOCK_DGRAM;
    break;
  }
  
  if(url_data->body != NULL)
    printf("body: %s\n", url_data->body);

  if(err) {
    char *header = create_header(url_data, user_agent, GET, HTTP_1_1);

    if(header == NULL) {
      printf("failed create_header\n");

      FREE(url_data->hostname);
      FREE(url_data->path_name);
      FREE(url_data->url);

      FREE(url_data);

      return FAI_CREATE_HEADER;
    }

    printf("request header:\n%s\n", header);

    socket_data_s socket_data;

    #ifdef _WIN32
    WSADATA wsaData;
    int wsa_error = WSAStartup(MAKEWORD(2, 0), &wsaData);
    #endif

    init_socket(&socket_data, af, socktype);

    err = set_addr_from_hostname(&socket_data, af, socktype, protocol, service, url_data);
    if (err != SUCCESS) {
      return err;
    }

    err = do_connect(&socket_data, url_data->protocol, is_ssl);
    if (err != SUCCESS) {
      return err;
    }
    
    err = send_data_and_revice_response(&socket_data, header, response);
    if(err != SUCCESS) {
      printf("Error: do_conenct\n");

      if (response->raw_header_size > 0) {
        FREE(response->raw_header);
        response->raw_header_size = 0;
      }

      FREE(header);
          
      FREE(url_data->hostname);
      FREE(url_data->path_name);
      FREE(url_data->url);
      FREE(url_data);

      return FAI_CONNECT;
    }


    FREE(header);

    FREE(url_data->hostname);
    FREE(url_data->path_name);
    FREE(url_data->url);
  }

  FREE(url_data);

  #ifdef _WIN32
    WSACleanup();
  #endif

  return SUCCESS;
}
