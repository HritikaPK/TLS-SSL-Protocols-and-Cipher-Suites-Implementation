#include "ssl_server.h"

#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <sstream>

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

  // IMPLEMENT HANDSHAKE HERE

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
