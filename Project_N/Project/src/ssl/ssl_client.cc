#include "ssl_client.h"

#include "stdlib.h"
#include "string.h"

#include <iostream>
#include <iomanip>

#include "dh.h"
#include "integer.h"
#include "osrng.h"

#include "tcp.h"
#include "crypto_adaptor.h"
#include "logger.h"
#include "utils.h"

using namespace std;

SslClient::SslClient() {
  string datetime;
  if ( get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0 ) {
    exit(1);
  }
  this->logger_ = new Logger(("ssl_client_"+datetime+".log"));
  this->tcp_->set_logger(this->logger_);

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Client Log at " + datetime);


}

SslClient::~SslClient() {
  if ( this->logger_ ) {
    delete this->logger_;
    this->logger_ = NULL;
    this->tcp_->set_logger(NULL);
  }
}

int SslClient::connect(const std::string &ip, int port, uint16_t cxntype) {

  // connect
  if ( this->tcp_->socket_connect(ip, port) != 0 ) {
    cerr << "Couldn't connect" << endl;
    return -1;
  }

  
  //client send ClientHello
  Record txClientHelloRecord;
  struct clientHello_struct {
	uint8_t handshakeType;
	uint16_t keyType;
  } clientHello;
  txClientHelloRecord.hdr.type = REC_HANDSHAKE;
  txClientHelloRecord.hdr.version = VER_99;
  clientHello.handshakeType = HS_CLIENT_HELLO;
  clientHello.keyType = cxntype;
  txClientHelloRecord.hdr.length = sizeof(clientHello);
  txClientHelloRecord.data = reinterpret_cast<char*>(&clientHello); 
  this->send(txClientHelloRecord);
  //cout  << hex << "C: " << clientHello.keyType << endl;

  //acknowledge ServerHello
  Record rxServerHelloRecord;
  this->recv(&rxServerHelloRecord);
  const char* rxServerHelloData = rxServerHelloRecord.data;
  uint8_t rxServerHandshakeType = static_cast<uint8_t>(*rxServerHelloData);
  //cout << "D: " << static_cast<int>(rxServerHandshakeType) << endl;
  if (rxServerHandshakeType != HS_SERVER_HELLO) {
	  cerr << "Server has not sent ServerHello" << endl;
	  return -1;
  }

  cout << "K" << endl;
  // recieving server certificate
  Record rxServerCertificateRecord;
  this->recv(&rxServerCertificateRecord);
  const char* rxServerCertificate = rxServerCertificateRecord.data;
  //cout << "L" << endl;
  //cout << rxServerCertificateRecord.hdr.length << endl;
  // for (size_t i = 0; i < rxServerCertificateRecord.hdr.length; ++i) {
  //         //cout << "Hello" << endl;
  //      std::cout << std::hex << std::setw(2) << std::setfill('0') << "Hello: " << static_cast<int>(rxServerCertificate[i]) << " ";    
  // }
  uint8_t rxServerCertHandshakeType = static_cast<uint8_t>(*rxServerCertificate);
  string certificate; //(rxServerCertificate + 1, rxServerCertificateRecord.hdr.length - 1);
  memcpy(&certificate,rxServerCertificate + sizeof(uint8_t), rxServerCertificateRecord.hdr.length-1);
  cout << "M: " << certificate << endl;
if (rxServerCertHandshakeType != HS_CERTIFICATE) {
        cerr << "Server has not sent ServerHelloDone" << endl;
        return -1;
}  
  //uint8_t rxServerCertificateHandshakeType = static_cast<uint8_t>(*rxServerCertificate);
  //TODO : add certificate verification


  //acknowledge server hellodone
  Record rxServerHelloDoneRecord;
  this->recv(&rxServerHelloDoneRecord);
  const char* rxServerHelloDoneData = rxServerHelloDoneRecord.data;
  uint8_t rxServerHelloDoneHandshakeType = static_cast<uint8_t>(*rxServerHelloDoneData);
  //cout << "F: "<< static_cast<int>(rxServerHelloDoneHandshakeType) << endl;
  if (rxServerHelloDoneHandshakeType != HS_SERVER_HELLO_DONE) {
	  cerr << "Server has not sent ServerHelloDone" << endl;
	  return -1;
  }



  return -1;
}

int SslClient::close() {
  int ret_code;
  ret_code = this->tcp_->socket_close();
  return ret_code;
}
