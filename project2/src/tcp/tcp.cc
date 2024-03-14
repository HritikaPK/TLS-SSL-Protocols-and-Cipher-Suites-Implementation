#include "tcp.h"

#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>  // gethostbyname
#include <unistd.h> // close
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h> // inet_ntoa

#include <iostream> // todo: remove this

#include "utils.h"

#define BIND_PORT_MIN 20000
#define BIND_PORT_MAX 20200

#define MAX_XFER_CHUNK_SIZE 1024

using namespace std;

#include "logger.h"

// Constructor & Destructor

TCP::TCP() {
  if ( this->init() != 0 ) {
    exit(1);
  }

  this->logger_ = NULL;
}

TCP::TCP(int sockfd, struct sockaddr_in sock_addr, socklen_t sock_addrlen) {
  this->sockfd_ = sockfd;
  this->sock_addr_ = sock_addr;
  this->sock_addrlen_ = sock_addrlen;
  this->logger_ = NULL;
}

TCP::~TCP() {

}

int TCP::init() {
  this->sockfd_ = -1;

  this->sock_addrlen_ = sizeof(this->sock_addr_);

  memset(&this->sock_addr_, 0, this->sock_addrlen_);
  this->sock_addr_.sin_family = AF_INET;
  this->sock_addr_.sin_addr.s_addr = htonl(INADDR_ANY);
  this->sock_addr_.sin_port = htons(0);

  if ( this->open_socket() != 0 ) {
    printf("Cannot open socket.\n");
    return -1;
  }

  if ( this->bind_port() != 0 ) {
    printf("Cannot bind port.\n");
    return -1;
  }

  return 0;
}

void TCP::set_logger(Logger *logger) {
  this->logger_ = logger;
  return;
}

Logger* TCP::get_logger() const {
  return this->logger_;
}



// socket() and bind()

int TCP::open_socket() {
  // returns -1 if error
  int sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ( sockfd >= 0 ) {
    this->sockfd_ = sockfd;
    return 0;
  }
  return -1;
}

int TCP::bind_port() {
  // returns -1 if error
  if( this->sockfd_ < 0 ) {
    fprintf(stderr, "bind_port(): sockfd_ has invalid value %d\n", this->sockfd_);
    return -1;
  }

  unsigned short port;  // 0 to 65535
  int retval;
  for ( port = BIND_PORT_MIN; port <= BIND_PORT_MAX; port++ ) {
    this->sock_addr_.sin_port = htons(port);
    retval = bind(this->sockfd_, (const struct sockaddr *)&this->sock_addr_, this->sock_addrlen_);
    if (retval >= 0) {
      return 0;
    }
  }

  // did not find a port
  return -1;
}

// listen(), accept(), connect()

int TCP::socket_listen(int num_ports) {
  int retcode;
  retcode = listen(this->sockfd_, num_ports);
  return retcode;
}

TCP* TCP::socket_accept() {
  int cxn_fd;
  struct sockaddr_in sock_addr;
  socklen_t sock_addrlen = sizeof(sock_addr);

  cxn_fd = accept(this->sockfd_, (struct sockaddr *)&sock_addr, &sock_addrlen); 
  if ( cxn_fd == -1 ) {
    return NULL;
  }

  TCP* new_tcp = new TCP(cxn_fd, sock_addr, sock_addrlen);
  return new_tcp;
}

int TCP::socket_connect(const std::string &ip_addr, int port) {
  int retcode;
  struct sockaddr_in cxn_addr; 
  struct hostent* host;

  memset(&cxn_addr, 0, sizeof(cxn_addr)); 

  cxn_addr.sin_family = AF_INET;
  cxn_addr.sin_port = htons(port);

  host = gethostbyname(ip_addr.c_str());
  memcpy(&cxn_addr.sin_addr, host->h_addr_list[0], host->h_length);

  retcode = connect(this->sockfd_, (struct sockaddr *)&cxn_addr, sizeof(cxn_addr));
  return retcode;
}

// send(), recv()

ssize_t TCP::socket_send(const std::string &send_str) {
  size_t send_str_len = send_str.length();
  char* send_buff = (char*)malloc(send_str_len*sizeof(char));
  memcpy( send_buff, send_str.c_str(), send_str_len);
  ssize_t send_len = socket_send(send_buff, send_str_len);
  free(send_buff);
  return send_len;
}

ssize_t TCP::socket_send(const char* send_buff, size_t send_exp_len) {
  size_t remain_send_len = send_exp_len;
  ssize_t send_total_len = 0;
  ssize_t send_len;
  const long unsigned int max_chunk_size = MAX_XFER_CHUNK_SIZE;
  int send_flags = 0;

  while ( remain_send_len > 0 ) {
    const char *chunk_start = &(send_buff[send_exp_len - remain_send_len]);
    send_len = remain_send_len > max_chunk_size ? max_chunk_size-1 : remain_send_len;
    send_len = send(this->sockfd_, chunk_start, send_len, send_flags);
    if ( send_len == -1 ) {
      perror("error when sending");
      return -1;
    }
    remain_send_len -= send_len;
  }

  send_total_len = send_exp_len - remain_send_len;

  if ( this->logger_ != NULL ) {
    this->logger_->log("sent:");
    this->logger_->log_raw(send_buff, send_total_len);
  }

  return send_total_len;
}


ssize_t TCP::socket_recv(string *recv_str, size_t recv_str_len) {
  char* recv_buff = (char*)malloc(recv_str_len*sizeof(char));
  ssize_t recv_len = socket_recv(recv_buff, recv_str_len);
  if ( recv_len == -1 ) {
    return -1;
  }
  *recv_str = string(recv_buff, recv_len);
  free(recv_buff);
  return recv_len;
}

ssize_t TCP::socket_recv(char* i_recv_buff, size_t recv_exp_len) {
  size_t remain_recv_len = recv_exp_len;
  ssize_t recv_total_len = 0;
  ssize_t recv_len = 0;
  const long unsigned int max_chunk_size = MAX_XFER_CHUNK_SIZE;
  char recv_buff[max_chunk_size];
  int recv_flags = 0;
  int index = 0;

  while ( remain_recv_len > 0 ) {
    memset(recv_buff, 0, max_chunk_size);
    recv_len = remain_recv_len > max_chunk_size ? max_chunk_size-1 : remain_recv_len;
    recv_len = recv(this->sockfd_, recv_buff, recv_len, recv_flags);
    if ( recv_len == -1 ) {
      perror("error when receiving");
      return -1;
    }
    index = recv_exp_len - remain_recv_len;
    memcpy( &(i_recv_buff[index]), recv_buff, recv_len);
    remain_recv_len -= recv_len;
  }

  recv_total_len = recv_exp_len - remain_recv_len;

  if ( this->logger_ != NULL ) {
    this->logger_->log("received:");
    this->logger_->log_raw(i_recv_buff, recv_total_len);
  }

  return recv_total_len;
}


int TCP::socket_close() {
  int retcode;
  retcode = close(this->sockfd_);
  return retcode;
}

// hostname() and port()

int TCP::get_hostname(std::string *hostname) const {
  return get_publichostname(hostname);
}

int TCP::get_port(int *port) const {
  if ( port != NULL ) {
    *port = (int)ntohs(this->sock_addr_.sin_port);
    return 0;
  }
  return -1;
}

