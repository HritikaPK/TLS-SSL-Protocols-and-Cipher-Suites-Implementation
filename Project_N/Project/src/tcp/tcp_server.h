#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include "tcp.h"

#include <string>
#include <vector>

class TcpServer: public TCP {
 public:
  TcpServer();
  virtual ~TcpServer();

  virtual int start(int num_clients=1000);
  virtual TCP* accept(); // blocking call
  virtual int shutdown();

  virtual std::vector<TCP*> get_clients() const;

  virtual int broadcast(const std::string &msg);

 private:
  std::vector<TCP*> clients_;
  bool closed_;
};

#endif // TCP_SERVER_H
