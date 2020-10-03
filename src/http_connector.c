#include "./http_connector.h"


int set_http_response_data(const char *response_data, ssize_t size, response_s *result)
{
  if(response_data == NULL) {
    printf("Error: response data is NULL\n");
    return -1;
  }

  if(size < 1) {
    printf("Error: size is less than one.\n");
    return -1;
  }

  char *header = INIT_ARRAY(char, size + 1);
  ssize_t count = 0;
  int new_line_count = 0;
  char previous = 0;
  // char **header_list = INIT_ARRAY(char*, 1);
  char *tmp_header_list_contents = NULL;
  ssize_t tmp_header_list_contents_size = 0;
  // int header_list_count = 0;
  for(ssize_t i = 0; i < size; ++i) {

    if(previous == '\n' && response_data[i] != '\r') {
      new_line_count = 0;
      previous = 0;

      /* if(tmp_header_list_contents != NULL) { */
      /* } */
      
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

    /* if(response_data[i] != '\r' && response_data[i] != '\n') { */
    /*   tmp_header_list_contents[tmp_header_list_contents_size] = response_data[i]; */
    /*   ++tmp_header_list_contents_size; */
    /* } */

    header[i] = response_data[i];
    
    ++count;

    if(new_line_count == 2)
      break;
    
  }

  if(count > MAX_HTTP_HEADER_SIZE) {
    FREE(header);

    printf("Error: over max http header size. Limit size: %d bytes\n", MAX_HTTP_HEADER_SIZE);
    
    return -1;
  }

  if(count >= size) {
    FREE(header);

    printf("Error: missing body\n");

    return -1;
  }
  header[count] = '\0';

  char *reallocated = realloc(header, count + 1);
  if(reallocated == NULL) {
    FREE(header);

    printf("Error: failed reallocate at header\n");

    return -1;
  }

  header = reallocated;

  char *body = INIT_ARRAY(char, size + 1);
  ssize_t body_pos = 0;
  for(ssize_t i = count; i < size; ++i) {
    body[body_pos] = response_data[i];
    ++body_pos;
  }
  body[body_pos] = '\0';

  result->body_size = body_pos + 1;
  result->body = body;

  result->raw_header_size = count;
  // result->header_size = strlen(header);
  result->raw_header = header;
  
  return 1;
}

void get_ipaddr_from_host(struct hostent *host, char **list)
{
  if(host->h_length > 4) {
    puts("v6");
    for(int i = 0; i < host->h_length - 1; ++i) {
      printf("%d\n", (unsigned char)*host->h_addr_list[i]);
    }
  } else {
    puts("v4");
    for(int i = 0; host->h_addr_list[i]; ++i) {

      unsigned char *byte_list = INIT_ARRAY(unsigned char, 4);

      byte_list[0] = (unsigned char)*host->h_addr_list[i];
      char first[3];
      sprintf(first, "%d", byte_list[0]);
      int size = strlen(first) + 4;

      for(int j = 1; j < 4; ++j) {
        byte_list[j] = (unsigned char)*(host->h_addr_list[i] + j);
        char tmp[3];
        sprintf(tmp, "%d", byte_list[j]);
        size += strlen(tmp);
      }

      char *result = INIT_ARRAY(char, size);
      sprintf(result, "%d.%d.%d.%d", byte_list[0], byte_list[1], byte_list[2], byte_list[3]);

      FREE(byte_list);

      list[i] = result;

      printf("%s\n", list[i]);

    }

  }
}

int resolve_hostname(const char* hostname, char **ip_list)
{

  struct hostent *tmp;
  tmp = gethostbyname(hostname);

  if(tmp == NULL) {
    fprintf(stderr, "gethostbyname() failed: %s\n", strerror(errno));
    return -1;
  }

  get_ipaddr_from_host(tmp, ip_list);

  return 1;
}

void init_socket(socket_data_s *socket_data)
{
  #ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
  #else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
  #endif

  struct sockaddr_in target;
  target.sin_family = AF_INET;
  // target.sin_port = htons(HTTP_PORT);
  // target.sin_port = htons(HTTPS_PORT);

  socket_data->socket = sock;
  socket_data->target = target;
  
}

void set_addr(socket_data_s *socket_data, const url_data_s *url_data)
{
  char **ip_list = INIT_ARRAY(char*, 1024);
  int err = resolve_hostname(url_data->hostname, ip_list);

  const char* addr = "127.0.0.1";

  if(ip_list[0] != NULL)
    addr = ip_list[0];

  socket_data->target.sin_addr.s_addr = inet_addr(addr);

  for(int i = 0; i < 1024; ++i) {
    if(ip_list[i] != NULL) {
      FREE(ip_list[i]);
      ip_list[i] = NULL;
    }
  }

  FREE(ip_list);
  
}

int do_connect(socket_data_s *socket_data, int protocol, int is_ssl, const char *data, response_s *response)
{

  if(protocol == HTTP_PORT)
    socket_data->target.sin_port = htons(HTTP_PORT);
  else
    socket_data->target.sin_port = htons(HTTPS_PORT);

  // const char *data = "GET / HTTP/1.1\r\nHost: madosuki.github.io\r\n\r\n";

  char *buf = INIT_ARRAY(char, BUF_SIZE);

  long readed_size = 0;

  int err;

  connect(socket_data->socket, (struct sockaddr *)&socket_data->target, sizeof(socket_data->target));

  /* #ifdef _WIN32
  /* bind(socket_data->socket, (struct sockaddr *)&socket_data->target, sizeof(socket_data->target)); */
  /* listen(socket_data->socket, 5); */
  /* #else */
  /* connect(socket_data->socket, (struct sockaddr *)&socket_data->target, sizeof(socket_data->target)); */
  /* #endif */

  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;

  if(is_ssl) {
    SSL_load_error_strings();
    SSL_library_init();

    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);

    ssl = SSL_new(ctx);

    err = SSL_set_fd(ssl, socket_data->socket);
    if(err == 0) {
      printf("SSL_set_fd error\n");
      
      FREE(buf);
      
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      
      close(socket_data->socket);
      
      return -1;
    }


    err = SSL_connect(ssl);
    if(err == 0) {
      printf("SSL_connect error\n");

      FREE(buf);
      
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      
      close(socket_data->socket);
      
      return -1;
    }

    
  }

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
  long result_size = 0;
  do{

    memcpy(&fds, &readfds, sizeof(fd_set));

    // first argument is must be that socket + 1. This value is max size of socket.
    err = select(socket_data->socket + 1, &fds, NULL, NULL, &tv);
    if(!err) {
      printf("timeout\n");
      break;
    }

    if(FD_ISSET(socket_data->socket, &fds)) {

      memset(buf, 0, BUF_SIZE);
    
      if(!is_ssl)
        readed_size = recv(socket_data->socket, buf, BUF_SIZE, 0);
      else
        readed_size = SSL_read(ssl, buf, BUF_SIZE);

      printf("count: %d, readed size: %ld\nbody: %s\n", count, readed_size, buf);
    }

    result_size += readed_size;
    if(result == NULL) {
      result = INIT_ARRAY(char, result_size);
      strncpy(result, buf, readed_size);
    } else {
      char *check_realloc = realloc(result, result_size);
      if(check_realloc != NULL)
        strcat(result, buf);
    }

    ++count;

  } while(readed_size > 0 && count < 3);


  if(is_ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_free_strings();
  }

  #ifdef _WIN32
    closesocket(socket_data->socket);
  #else
    close(socket_data->socket);
  #endif

  FREE(buf);

  // response_s *tmp_response = INIT_ARRAY(response_s, sizeof(response_s));

  if(set_http_response_data(result, strlen(result), response)) {
    printf("header size: %ld\nheader: %s\n\nbody size: %ld\nbody: %s\n",
           response->raw_header_size,
           response->raw_header,
           response->body_size,
           response->body);

    // FREE(tmp_response->raw_header);
    // FREE(tmp_response->body);
  }
  
  FREE(result);  

  // FREE(tmp_response);

  // response = tmp_response;


  return 1;
}

int set_url_data(const char *url, ssize_t url_size, const char *data, ssize_t data_size, Method method, url_data_s *url_data)
{
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

  if(strcmp(check_protocol, "http://") == 0) {
    is_valid_protocol = 1;
    protocol = HTTP_PORT;
  }
  else if(strcmp(check_protocol, "https:/") == 0) {
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
  /* int is_get_query = 0; */
  /* ssize_t get_query_pos = 0; */
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


int get_http_response(const char *url, const char *user_agent, response_s *response)
{

  url_data_s *url_data = (url_data_s*)malloc(sizeof(url_data_s));
  int err = set_url_data(url, strlen(url), NULL, 0, GET, url_data);
  if(err == -1) {
    FREE(url_data);
    puts("Error: failed set_url_data in get_http_response\n");
    return -1;
  }
  
  printf("hostname: %s\n", url_data->hostname);
  printf("pathname: %s\n", url_data->path_name);

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

      return -1;
    }

    printf("request header: %s\n", header);

    socket_data_s socket_data;

    #ifdef _WIN32
    WSADATA wsaData;
    int wsa_error = WSAStartup(MAKEWORD(2, 0), &wsaData);
    #endif

    init_socket(&socket_data);

    set_addr(&socket_data, url_data);

    /* response_s *response = INIT_ARRAY(response_s, sizeof(response_s)); */
    /* if(response == NULL) { */
    /*   printf("failed malloc to response at do_connect\n"); */
      
    /*   FREE(header); */
          
    /*   FREE(url_data->hostname); */
    /*   FREE(url_data->path_name); */
    /*   FREE(url_data->url); */
    /*   FREE(url_data); */

    /*   return -1; */
    /* } */

    int protocol = HTTPS_PORT;
    if(url_data->protocol == HTTP_PORT)
      protocol = HTTP_PORT;
    
    err = do_connect(&socket_data, protocol, 1, header, response);
    if(!err) {
      printf("Error: do_conenct\n");

      FREE(header);
          
      FREE(url_data->hostname);
      FREE(url_data->path_name);
      FREE(url_data->url);
      FREE(url_data);

      return -1;
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

  return 1;
}
