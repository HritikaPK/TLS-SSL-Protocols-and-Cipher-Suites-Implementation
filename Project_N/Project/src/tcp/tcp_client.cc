#include "tcp_client.h"

#include <stdlib.h>

#include "logger.h"
#include "utils.h"

using namespace std;

TcpClient::TcpClient() {
  string datetime;
  if ( get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0 ) {
    exit(1);
  }
  set_logger(new Logger("client_"+datetime+".log"));

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Client Log at " + datetime);

}

TcpClient::~TcpClient() {
  if ( this->logger_ ) {
    delete this->logger_;
    set_logger(NULL);
  }
}

int TcpClient::connect(const std::string &ip, int port) {
  return socket_connect(ip, port);
}

ssize_t TcpClient::send(const std::string &send_str) {
  return socket_send(send_str);
}

ssize_t TcpClient::recv(std::string *recv_str, size_t recv_len) {
  return socket_recv(recv_str, recv_len);
}

int TcpClient::close() {
  return socket_close();
}



