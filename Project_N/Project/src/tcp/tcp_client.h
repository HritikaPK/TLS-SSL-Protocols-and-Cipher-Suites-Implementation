#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include "tcp.h"

#include <string>
#include <vector>

class TcpClient: public TCP {
 public:
  TcpClient();
  virtual ~TcpClient();

  virtual int connect(const std::string &ip, int port);

  virtual ssize_t send(const std::string &send_str);
  virtual ssize_t recv(std::string *recv_str, size_t recv_len);

  virtual int close();

};

#endif // TCP_CLIENT_H
