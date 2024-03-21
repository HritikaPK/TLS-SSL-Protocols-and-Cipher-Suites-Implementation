#include "ssl_server.h"

#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <sstream>
#include <iomanip> //todel

#include "dh.h"
#include "integer.h"
#include "osrng.h"

#include "crypto_adaptor.h"
#include "tcp.h"
#include "logger.h"
#include "utils.h"

using namespace std;

SslServer::SslServer() {
  string datetime;
  if ( get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0 ) {
    exit(1);
  }
  this->logger_ = new Logger(("ssl_server_"+datetime+".log"));
  this->tcp_->set_logger(this->logger_);

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Server Log at " + datetime);

  this->closed_ = false;

  // init dhe
  generate_pqg(this->dh_p_, this->dh_q_, this->dh_g_);

  // init rsa
  generate_rsa_keys(this->private_key_, this->public_key_);
}

SslServer::~SslServer() {
  if ( !this->closed_ ) {
    this->shutdown();
  }
  delete this->logger_;
}


int SslServer::start(int num_clients) {
  if ( this->closed_ ) {
    return -1;
  }

  return this->tcp_->socket_listen(num_clients);
}

SSL* SslServer::accept() {
  if ( this->closed_ ) {
    return NULL;
  }

  TCP* cxn = this->tcp_->socket_accept();
  if ( cxn == NULL ) {
    cerr << "error when accepting" << endl;
    return NULL;
  }

  cxn->set_logger(this->logger_);

  SSL* new_ssl_cxn = new SSL(cxn);
  this->clients_.push_back(new_ssl_cxn);

  //server receives ClientHello
  Record rxClientHelloRecord;
  Record txServerHelloRecord;
  //wait until ClientHello is received
  do {
	cout << "I: Waiting for ClientHello" << endl;
	new_ssl_cxn->recv(&rxClientHelloRecord);
  } while (sizeof(rxClientHelloRecord) == 0) ;
  const char* rxClientHelloData = rxClientHelloRecord.data;
  uint8_t rxClientHandshakeType = static_cast<uint8_t>(*rxClientHelloData);
  uint16_t rxClientKeyType;
 memcpy(&rxClientKeyType, rxClientHelloData + sizeof(uint16_t), sizeof(uint16_t));
  
  //server starts ServerHello
  struct serverHello_struct {
  	uint8_t ServerHandshakeType;
  	uint16_t ServerKeyType;
  } serverHello;  
  if (rxClientHelloRecord.hdr.type != REC_HANDSHAKE) {
	  cerr << "ClientHello has not been sent as a Record Handshake" << endl;
	  return NULL;
  }
  txServerHelloRecord.hdr.type = rxClientHelloRecord.hdr.type;
  if (rxClientHelloRecord.hdr.version != VER_99) {
	  cerr << "TLS version sent by client not supported by server" << endl;
	  return NULL;
  }
  txServerHelloRecord.hdr.version = rxClientHelloRecord.hdr.version;
  if (rxClientHandshakeType != HS_CLIENT_HELLO) {
	  cerr << "Client did not send ClientHello" << endl;
	  return NULL;
  }
  serverHello.ServerHandshakeType = HS_SERVER_HELLO;
  //cout << hex << "H: " << rxClientKeyType << endl;
  if (!(rxClientKeyType == KE_DHE || rxClientKeyType == KE_RSA || rxClientKeyType == KE_DH)) {
	  cerr << "Server can support only DHE or RSA encryption" << endl;
	  return NULL;
  }  
  serverHello.ServerKeyType = rxClientKeyType;
  txServerHelloRecord.hdr.length = sizeof(serverHello);
  txServerHelloRecord.data = reinterpret_cast<char*>(&serverHello);
  new_ssl_cxn->send(txServerHelloRecord);


  //server generates the keys and sends public key to client
  
  if (rxClientKeyType == KE_RSA) {

  //CryptoPP::RSA::PrivateKey private_key;
  //CryptoPP::RSA::PublicKey public_key;
  //generate_rsa_keys(private_key, public_key);

  //stringstream ss;
  //this->public_key.Save(ss);
  //string public_key_str = ss.str(); //we have stored the public key here as sstream
  string public_key_str;
  CryptoPP::StringSink public_key_ss(public_key_str);
  this->public_key_.DEREncode(public_key_ss);

  Record txServerCertificateRecord;
  struct serverCertificate_struct{
        uint8_t handshakeType;
        string certificate;
  }serverCertificate;


  serverCertificate.handshakeType = HS_CERTIFICATE;
  serverCertificate.certificate = public_key_str;

  //cout << hex << "G: " << static_cast<int>(serverCertificate.handshakeType) << endl;
  cout << "H: " << public_key_str << endl;

  txServerCertificateRecord.hdr.type = REC_HANDSHAKE;
  txServerCertificateRecord.hdr.version = VER_99;
  txServerCertificateRecord.hdr.length = sizeof(serverCertificate);
  txServerCertificateRecord.data = reinterpret_cast<char*>(&serverCertificate);
  new_ssl_cxn->send(txServerCertificateRecord); //server has sent the certificate
 }
 

// server waits for client to send encrypted(sharedkey) .......


  //server sends ServerDone
  Record txServerHelloDoneRecord;
  struct ServerHelloDone_struct {
	  uint8_t handshakeType;
  } serverHelloDone;
  txServerHelloDoneRecord.hdr.type = REC_HANDSHAKE;
  txServerHelloDoneRecord.hdr.version = VER_99;
  serverHelloDone.handshakeType = HS_SERVER_HELLO_DONE;
  txServerHelloDoneRecord.hdr.length = sizeof(serverHelloDone); 
  txServerHelloDoneRecord.data = reinterpret_cast<char*>(&serverHelloDone);
  new_ssl_cxn->send(txServerHelloDoneRecord);
  //cout << "E: "<< static_cast<int>(serverHelloDone.handshakeType) << endl;


  

  return NULL;
}

int SslServer::shutdown() {
  if ( this->closed_ ) {
    return -1;
  }

  // pop all clients
  while ( !this->clients_.empty() ) {
    SSL* cxn = this->clients_.back();
    this->clients_.pop_back();
    if ( cxn != NULL ) {
      delete cxn;
    }
  }
  return 0;
}

vector<SSL*> SslServer::get_clients() const {
  return vector<SSL*>(this->clients_);
}

int SslServer::broadcast(const string &msg) {
  if ( this->closed_ ) {
    return -1;
  }

  int num_sent = 0;

  // this->logger_->log("broadcast:");
  // this->logger_->log_raw(msg);

  for ( vector<SSL*>::iterator it = this->clients_.begin() ;
        it != this->clients_.end() ; ++it ) {
    ssize_t send_len;
    send_len = (*it)->send(msg);
    if ( send_len == (unsigned int)msg.length() ) {
      num_sent += 1;
    }
  }

  return num_sent;
}
