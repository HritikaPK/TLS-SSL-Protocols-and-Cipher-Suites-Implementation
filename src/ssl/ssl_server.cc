#include "ssl_server.h"
#include <base64.h>
#include <files.h>
#include <rsa.h>
#include <oaep.h>

#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <sstream>
#include <iomanip>

#include "dh.h"
#include "integer.h"
#include "osrng.h"
#include "hkdf.h"

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

  //server waits for client to establish connection using ClientHello
  Record rxClientHelloRecord;
  do {
        new_ssl_cxn->recv(&rxClientHelloRecord);
  } while (sizeof(rxClientHelloRecord) == 0) ;
  char* rxClientHelloData = rxClientHelloRecord.data;
  uint8_t rxClientHandshakeType1 = static_cast<uint8_t>(*rxClientHelloData);
  uint16_t rxClientKeyType;
  memcpy(&rxClientKeyType, rxClientHelloData + 2*sizeof(uint8_t), sizeof(uint16_t));
  
  if (rxClientHelloRecord.hdr.type != REC_HANDSHAKE) {
          cerr << "ClientHello has not been sent as a Record Handshake" << endl;
          return NULL;
  }
  if (rxClientHelloRecord.hdr.version != VER_99) {
          cerr << "TLS version sent by client not supported by server" << endl;
          return NULL;
  }
  if (rxClientHandshakeType1 != HS_CLIENT_HELLO) {
          cerr << "Client did not send ClientHello" << endl;
          return NULL;
  }
  if (!(rxClientKeyType == KE_DHE || rxClientKeyType == KE_RSA || rxClientKeyType == KE_DH)) {
          cerr << "Server can support only DHE or RSA encryption in TLS" << endl;
          return NULL;
  }

  string public_key_str;
  std::string serializedData;
  CryptoPP::StringSink public_key_ss(public_key_str);
  
  if (rxClientKeyType == KE_DHE) {
	//TLS handshake performed using DHE key establishment
    this->logger_->log_raw("DHE Key");
	CryptoPP::DH dh;
    dh.AccessGroupParameters().Initialize(this->dh_p_,this->dh_q_,this->dh_g_);
    CryptoPP::Integer privateKeyDHE, publicKeyDHE;
	CryptoPP::AutoSeededRandomPool rng;
    privateKeyDHE.Randomize(rng, CryptoPP::Integer::One(), CryptoPP::Integer::Power2(2048));

    // Calculate the public key corresponding to the private key
	// public_key = (g ^ private_key) mod p
    publicKeyDHE = a_exp_b_mod_c(this->dh_g_, privateKeyDHE, this->dh_p_);
	//public key encrypted using DER Encode
	publicKeyDHE.DEREncode(public_key_ss); 
	
    string dh_p_str, dh_g_str;
	//g and p are also encrypted, since the server sends them to client
    CryptoPP::StringSink dh_p_ss(dh_p_str);
    CryptoPP::StringSink dh_g_ss(dh_g_str);
	this->dh_p_.DEREncode(dh_p_ss);
	this->dh_g_.DEREncode(dh_g_ss);

    struct serverCertificate_struct {
       std::uint8_t handshakeType1; 
       std::uint8_t handshakeType2; 
       std::uint8_t handshakeType3; 
       std::uint8_t handshakeType4; 
       std::uint8_t handshakeType5; 
       std::string certificate_public_key; 
       std::string certificate_dh_p; 
       std::string certificate_dh_g; 
    };
    
    serverCertificate_struct serverCertificate;

    serverCertificate.handshakeType1 = HS_SERVER_HELLO;
    serverCertificate.handshakeType2 = HS_CERTIFICATE;
    serverCertificate.handshakeType3 = HS_SERVER_KEY_EXCHANGE;
    serverCertificate.handshakeType4 = HS_CERTIFICATE_REQUEST;
    serverCertificate.handshakeType5 = HS_SERVER_HELLO_DONE;
    serverCertificate.certificate_public_key = public_key_str;
    serverCertificate.certificate_dh_p = dh_p_str;
    serverCertificate.certificate_dh_g = dh_g_str;


	//serialising the data to be sent via record
    stringstream serial_data_ss;
    serial_data_ss << hex << serverCertificate.handshakeType1;
    serial_data_ss << hex << serverCertificate.handshakeType2;
    serial_data_ss << hex << serverCertificate.handshakeType3;
    serial_data_ss << hex << serverCertificate.handshakeType4;
    serial_data_ss << hex << serverCertificate.handshakeType5;
    serial_data_ss << serverCertificate.certificate_public_key << "\n|\n" << serverCertificate.certificate_dh_p << "\n|\n" << serverCertificate.certificate_dh_g; 
    serializedData = serial_data_ss.str();
    Record txServerCertificateRecord;
    txServerCertificateRecord.hdr.type = REC_HANDSHAKE;
    txServerCertificateRecord.hdr.version = VER_99;
    txServerCertificateRecord.hdr.length = serializedData.length();
    txServerCertificateRecord.data = const_cast<char*>(serializedData.data());
	//server sending its packet to client
    new_ssl_cxn->send(txServerCertificateRecord);

	//server waits for client to respond with its certificate information
	Record rxPreMasterBundleDHERecord;
	new_ssl_cxn->recv(&rxPreMasterBundleDHERecord);
    const char* rxClientResponse = rxPreMasterBundleDHERecord.data;
    const char* ClientPublicKeyPtr = rxClientResponse + 4;

    const uint16_t ClientPublicKeyLength = rxPreMasterBundleDHERecord.hdr.length-4;
    string upper_nibble_handshake_type(1,rxClientResponse[1]);
    string lower_nibble_handshake_type(1,rxClientResponse[2]);
    string handshake_type_str = upper_nibble_handshake_type+lower_nibble_handshake_type;
    uint8_t rxClientCertificateHandshakeType = *rxClientResponse; 
    uint8_t rxClientCertificateVerifyHandshakeType = *(rxClientResponse+3);
    uint8_t rxPMKHandshakeType = stoi(handshake_type_str,nullptr,16);

    if (rxClientCertificateHandshakeType != HS_CERTIFICATE) {
      	  cerr << "Client has not sent its certificate" << endl;
		  return NULL;
	}
    if (rxPMKHandshakeType != HS_CLIENT_KEY_EXCHANGE) {
      	  cerr << "Client has not sent it's public key" << endl;
		  return NULL;
	}
    if (rxClientCertificateVerifyHandshakeType != HS_CERTIFICATE_VERIFY) {
		  cerr << "Client certificate has not been verified" << endl;
		  return NULL;
	}
	string client_public_key_encoded;
	client_public_key_encoded.resize(ClientPublicKeyLength);
	memcpy(&client_public_key_encoded[0],ClientPublicKeyPtr,rxPreMasterBundleDHERecord.hdr.length);
	client_public_key_encoded[ClientPublicKeyLength] = '\0';

	CryptoPP::Integer clientPublicKeyDHE;
    CryptoPP::StringSource client_public_key_source(client_public_key_encoded, true);
	//server decrypts reeceived client's public key using BER Decode
	clientPublicKeyDHE.BERDecode(client_public_key_source); 
	CryptoPP::Integer serverPreMasterSharedKey;
	//server generates pre_master_secret = (client_public_key ^ server_private_key) mod p
	serverPreMasterSharedKey = a_exp_b_mod_c(clientPublicKeyDHE, privateKeyDHE, this->dh_p_); 

	
    // Convert the shared secret key to byte representation
	stringstream PreMasterSharedKey_ss;
	PreMasterSharedKey_ss << hex << serverPreMasterSharedKey;
    string PreMasterSharedKeyStr = PreMasterSharedKey_ss.str();
	//cout << "Server generates DHE premaster key as " << PreMasterSharedKeyStr << endl;

    const size_t shared_key_length = 16; 
    const size_t salt_length = 0; 
    const size_t info_length = 0; 

    // Perform session key derivation using HKDF
    byte session_keys_DHE[shared_key_length]; 
	CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(session_keys_DHE, sizeof(session_keys_DHE), reinterpret_cast<const byte*>(PreMasterSharedKeyStr.data()), PreMasterSharedKeyStr.length(), nullptr, salt_length, nullptr, info_length);

    //set the shared session key for this client connection 
	new_ssl_cxn->set_shared_key(session_keys_DHE,shared_key_length);
	//extra logic to convert master key from byte to string for display purpose only
	//stringstream SsessionKey_ss;
	//string SsessionKey_str;
	//for (size_t i = 0 ; i < shared_key_length ; i++) {
	//	SsessionKey_ss << hex << static_cast<int>(session_keys_DHE[i]);
	//}
	//SsessionKey_str = SsessionKey_ss.str();
	//cout << "Server generates DHE master key as " << SsessionKey_str << endl;

  }

  if (rxClientKeyType == KE_RSA) {
	//TLS handshake performed in case of RSA key establishment
    this->logger_->log_raw("RSA Key");
	string public_key_str;
	CryptoPP::StringSink public_key_ss(public_key_str);
	//encode the public key generated using generate_rsa using DER Encode, to be sent to the client
	this->public_key_.DEREncode(public_key_ss); 
	    
	struct serverCertificate_struct {
	       std::uint8_t handshakeType1; 
	       std::uint8_t handshakeType2; 
	       std::uint8_t handshakeType3; 
	       std::uint8_t handshakeType4; 
	       std::uint8_t handshakeType5; 
	       std::string certificate; 
	    };
	    
	serverCertificate_struct serverCertificate;
	serverCertificate.handshakeType1 = HS_SERVER_HELLO;
	serverCertificate.handshakeType2 = HS_CERTIFICATE;
	serverCertificate.handshakeType3 = HS_SERVER_KEY_EXCHANGE;
	serverCertificate.handshakeType4 = HS_CERTIFICATE_REQUEST;
	serverCertificate.handshakeType5 = HS_SERVER_HELLO_DONE;
	serverCertificate.certificate = public_key_str;
	
	//serialize the data to be sent to the client
	stringstream serial_data_ss;
	serial_data_ss << hex << serverCertificate.handshakeType1;
	serial_data_ss << hex << serverCertificate.handshakeType2;
	serial_data_ss << hex << serverCertificate.handshakeType3;
	serial_data_ss << hex << serverCertificate.handshakeType4;
	serial_data_ss << hex << serverCertificate.handshakeType5;
	serial_data_ss << serverCertificate.certificate; 
	serializedData = serial_data_ss.str();
	
	//server sending its packet to the client
	Record txServerCertificateRecord;
	txServerCertificateRecord.hdr.type = REC_HANDSHAKE;
	txServerCertificateRecord.hdr.version = VER_99;
	txServerCertificateRecord.hdr.length = serializedData.length();
	txServerCertificateRecord.data = const_cast<char*>(serializedData.data());
	new_ssl_cxn->send(txServerCertificateRecord);
	
	//server receives the encrypted pre-master shared key from client
	Record rxPreMasterkeyRecord;
	new_ssl_cxn->recv(&rxPreMasterkeyRecord);
	const char* rxClientResponse = rxPreMasterkeyRecord.data;
	const char* PMKData = rxClientResponse + 4;
	const uint16_t PMKeyLength = rxPreMasterkeyRecord.hdr.length-4;
	string upper_nibble_handshake_type(1,rxClientResponse[1]);
	string lower_nibble_handshake_type(1,rxClientResponse[2]);
	string handshake_type_str = upper_nibble_handshake_type+lower_nibble_handshake_type;
	uint8_t rxClientCertificateHandshakeType = *rxClientResponse; 
	uint8_t rxClientCertificateVerifyHandshakeType = *(rxClientResponse+3);
	uint8_t rxPMKHandshakeType = stoi(handshake_type_str,nullptr,16);
	
	if (rxClientCertificateHandshakeType != HS_CERTIFICATE) {
	  	  cerr << "Client has not sent its certificate" << endl;
		  return NULL;
	}
	if (rxPMKHandshakeType != HS_CLIENT_KEY_EXCHANGE) {
	  	  cerr << "Client has not sent it's public key" << endl;
		  return NULL;
	}
	if (rxClientCertificateVerifyHandshakeType != HS_CERTIFICATE_VERIFY) {
		  cerr << "Client certificate has not been verified" << endl;
		  return NULL;
	}
	string PMKey;
	PMKey.resize(PMKeyLength);
	memcpy(&PMKey[0],PMKData,rxPreMasterkeyRecord.hdr.length);
	PMKey[PMKeyLength] = '\0';
	
	string decrypted_PM;
	const unsigned char* decrypted_PM_bytes; 
	int result = rsa_decrypt(private_key_,&decrypted_PM, PMKey); //decrypt the encrypted pre-master shared key
	if (result == 0) {
		decrypted_PM_bytes = reinterpret_cast<const unsigned char*>(decrypted_PM.data());
	} else {
		std::cerr << "Decryption failed!" << std::endl;
		return NULL;
	}
	
	//extra logic only for printing premaster key
	//stringstream preMasterSecret_ss;
	//for (size_t i = 0 ; i < 20; i++) {
	//		preMasterSecret_ss << hex << static_cast<int>(decrypted_PM_bytes[i]);
	//}
	//string preMasterSecret_str = preMasterSecret_ss.str();
	//cout << "Server decrypted RSA premaster key as " << preMasterSecret_str << endl;

	byte SsessionKey[16];
	// Perform key derivation using HKDF (HMAC-based Key Derivation Function)
	CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
	hkdf.DeriveKey(SsessionKey, sizeof(SsessionKey), decrypted_PM_bytes, decrypted_PM.length(), nullptr, 0, nullptr, 0);
    
    //set the shared session key for this client connection	
	new_ssl_cxn->set_shared_key(SsessionKey, 16);
	//extra logic to convert master key from byte to string for display purpose only
	//stringstream SsessionKey_ss;
	//string SsessionKey_str;
	//for (size_t i = 0 ; i < 16 ; i++) {
	//	SsessionKey_ss << hex << static_cast<int>(SsessionKey[i]);
	//}
	//SsessionKey_str = SsessionKey_ss.str();
	//cout << "Server generates RSA master key as " << SsessionKey_str << endl;
  }

  //session keys are generated at the server side, wait for client to send handshake-finished 
  Record rxClientFinishedRecord;
  new_ssl_cxn->recv(&rxClientFinishedRecord);
  uint8_t rxClientHandshakeType = static_cast<int>(*rxClientFinishedRecord.data);
  if (rxClientHandshakeType != HS_FINISHED) {
		  cerr << "Client has not finished the TLS handshake" << endl;
		  return NULL;
  }

  //server responds to client's hanshake finished by sending handshake-finished
  uint8_t server_finished_handshake = HS_FINISHED;
  Record txServerFinishedRecord;
  txServerFinishedRecord.hdr.type = REC_HANDSHAKE;
  txServerFinishedRecord.hdr.version = VER_99;
  txServerFinishedRecord.hdr.length = sizeof(server_finished_handshake);
  txServerFinishedRecord.data = reinterpret_cast<char*>(&server_finished_handshake);
  new_ssl_cxn->send(txServerFinishedRecord);

  //TLS handshake has been successfully established for this client
  return new_ssl_cxn;
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
