#ifndef TCP_H
#define TCP_H

#include <string>
#include <vector>
#include <netinet/in.h>   // sockaddr_in, PF_INET

class Logger;

class TCP {
 public:
  TCP();
  virtual ~TCP();

  void set_logger(Logger *logger);
  Logger* get_logger() const;

  int get_hostname(std::string *hostname) const;
  int get_port(int *port) const;

  virtual int socket_listen(int num_ports);
  virtual TCP* socket_accept();

  virtual int socket_connect(const std::string &ip, int port);

  virtual ssize_t socket_send(const std::string &send_str);
  virtual ssize_t socket_send(const char* send_buff, size_t send_len);
  virtual ssize_t socket_recv(std::string *recv_str, size_t recv_len);
  virtual ssize_t socket_recv(char* recv_buff, size_t recv_len);

  virtual int socket_close();

 protected:
  TCP(int sockfd, struct sockaddr_in sock_addr, socklen_t sock_addrlen);

  int init();
  int open_socket();
  int bind_port();

  Logger* logger_;

 private:
  int sockfd_;
  struct sockaddr_in sock_addr_;
  socklen_t sock_addrlen_;
};

#endif // TCP_H
