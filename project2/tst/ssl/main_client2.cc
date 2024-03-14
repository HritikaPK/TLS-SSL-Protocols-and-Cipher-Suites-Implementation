#include <iostream>
#include <fstream>

#include "ssl_client.h"

using namespace std;

int main(int argc, char* argv[]) {
  string c_idx = "0";
  if ( argc > 1 ) {
    c_idx = string(argv[1]);
  }

  string hostname;
  int port;

  ifstream addrfile;
  addrfile.open("address.txt");
  addrfile >> hostname;
  addrfile >> port;
  addrfile.close();

  SslClient* ssl_client = new SslClient();

  if ( ssl_client->connect(hostname, port, SSL::KE_RSA) < 0 ) {
    cout << "\tc[" << c_idx << "]: couldn't connect" << endl;
    return 1;
  }

  cout << "\tc[" << c_idx << "]: connected " << endl;

  if ( ssl_client->send("client says hello") < 0 ) {
    cout << "\tc[" << c_idx << "]: couldn't send" << endl;
    return 1;
  }

  cout << "\tc[" << c_idx << "]: sent " << endl;

  string recv_buff;
  if ( ssl_client->recv(&recv_buff) < 0 ) {
    cout << "\tc[" << c_idx << "]: couldn't receive" << endl;
    return 1;
  }

  cout << "\tc[" << c_idx << "]: received " << endl;

  cout << "\tc[" << c_idx << "]: '" << recv_buff << "'" << endl;

  cout << "\tc[" << c_idx << "]: closing" << endl;

  if ( ssl_client->close() < 0 ) {
    cout << "\tc[" << c_idx << "]: couldn't close" << endl;
    return 1;
  }

  cout << "\tc[" << c_idx << "]: closed" << endl;

  delete ssl_client;

  cout << "\tc[" << c_idx << "]: exiting" << endl;

  return 0;
}

