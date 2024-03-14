#include "tcp_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <iostream>
#include <fstream>

#include "logger.h"
#include "utils.h"

using namespace std;

TcpServer::TcpServer() {
  string datetime;
  if ( get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0 ) {
    exit(1);
  }
  set_logger(new Logger("server_"+datetime+".log"));

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Server Log at " + datetime);

  this->closed_ = false;
}

TcpServer::~TcpServer() {
  if ( !this->closed_ ) {
    this->shutdown();
  }
  if ( this->logger_ ) {
    delete this->logger_;
    set_logger(NULL);
  }
}

int TcpServer::start(int num_client) {
  if ( this->closed_ ) {
    return -1;
  }

  return socket_listen(num_client);
}

TCP* TcpServer::accept() {
  /* Note: do not delete the cxn in main */
  if ( this->closed_ ) {
    return NULL;
  }

  TCP* cxn = socket_accept();
  cxn->set_logger(this->get_logger());
  this->clients_.push_back(cxn);
  return cxn;
}

int TcpServer::shutdown() {
  if ( this->closed_ ) {
    return -1;
  }

  while ( !this->clients_.empty() ) {
    TCP* cxn = this->clients_.back();
    this->clients_.pop_back();
    if ( cxn != NULL ) {
      cxn->socket_close();
      delete cxn;
    }
  }

  return 0;
}

vector<TCP*> TcpServer::get_clients() const {
  vector<TCP*> ret_vector(this->clients_);
  return ret_vector;
}

int TcpServer::broadcast(const string &msg) {
  if ( this->closed_ ) {
    return -1;
  }

  int retval = 0;

  this->logger_->log("broadcast:");
  this->logger_->log_raw(msg);

  for ( vector<TCP*>::iterator it = this->clients_.begin() ;
        it != this->clients_.end() ; ++it ) {
    ssize_t send_len;
    send_len = (*it)->socket_send(msg);
    if ( send_len != (unsigned int)msg.length() ) {
      retval = 1;
    }
  }

  return retval;
}



