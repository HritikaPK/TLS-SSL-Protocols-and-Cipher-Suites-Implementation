#ifndef SSL_H
#define SSL_H

#include <stdint.h>

#include <string>

class TCP;
class Logger;

class SSL {
 // some types and constants
 public:
  //////////////////////////////////////////////
  // SSL Record

  struct RecordHeader {
    uint8_t type;
    uint16_t version;
    uint16_t length;
  };

  struct Record {
    RecordHeader hdr;
    char* data;
  };

  // record type
  static const uint8_t REC_CHANGE_CIPHER_SPEC = 0x14;
  static const uint8_t REC_ALERT              = 0x15;
  static const uint8_t REC_HANDSHAKE          = 0x16;
  static const uint8_t REC_APP_DATA           = 0x17;

  // record version
  static const uint16_t VER_99 = 0x0909;

  //////////////////////////////////////////////
  // Handshake types

  static const uint8_t HS_HELLO_REQUEST       = 0x00;
  static const uint8_t HS_CLIENT_HELLO        = 0x01;
  static const uint8_t HS_SERVER_HELLO        = 0x02;
  static const uint8_t HS_CERTIFICATE         = 0x0B;
  static const uint8_t HS_SERVER_KEY_EXCHANGE = 0x0C;
  static const uint8_t HS_CERTIFICATE_REQUEST = 0x0D;
  static const uint8_t HS_SERVER_HELLO_DONE   = 0x0E;
  static const uint8_t HS_CERTIFICATE_VERIFY  = 0x0F;
  static const uint8_t HS_CLIENT_KEY_EXCHANGE = 0x10;
  static const uint8_t HS_FINISHED            = 0x14;

  // KeyExchange types
  static const uint16_t KE_DHE = 0x0000;
  static const uint16_t KE_DH  = 0x0001;
  static const uint16_t KE_RSA = 0x0002;

 //////////////////////////////////////////////
 // ssl functions
 public:
  SSL();
  SSL(TCP* tcp);
  virtual ~SSL();

  std::string get_hostname() const;
  int get_port() const;

  // for strings
  virtual int send(const std::string &send_str);
  virtual int recv(std::string *recv_str);

  // for records
  virtual int send(const Record &send_record);
  virtual int recv(Record *recv_record);

  // for key
  virtual int set_shared_key(const unsigned char * const shared_key, size_t key_len);

 protected:
  TCP* tcp_;
  Logger* logger_;
  unsigned char* shared_key_;
  size_t shared_key_len_;

};


#endif // SSL_H
