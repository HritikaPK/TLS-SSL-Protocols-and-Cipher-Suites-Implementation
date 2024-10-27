#ifndef SSL_CLIENT_H
#define SSL_CLIENT_H

#include "ssl.h"

#include <sys/types.h>

#include <string>
#include <vector>
#include <iostream>
#include <sstream>
using namespace std;

class SslClient: public SSL {
 public:
  SslClient();
  virtual ~SslClient();

  virtual int connect(const std::string &ip, int port, uint16_t cxntype);

  virtual int close();

 private:

};

#endif // SSL_CLIENT_H
