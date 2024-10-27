#include "ssl_client.h"
#include <base64.h>

#include "stdlib.h"
#include "string.h"
#include "hkdf.h"

#include <iostream>
#include <iomanip>
#include <sstream>

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

  //client sends ClientHello to server to establish TLS handshake
  Record txClientHelloRecord;
  struct clientHello_struct {
        uint8_t handshakeType1;
        uint16_t keyType;
  } clientHello;
  txClientHelloRecord.hdr.type = REC_HANDSHAKE;
  txClientHelloRecord.hdr.version = VER_99;
  clientHello.handshakeType1 = HS_CLIENT_HELLO;
  clientHello.keyType = cxntype; //client sends cipher suite as DHE/RSA as part of ClientHello
  txClientHelloRecord.data = reinterpret_cast<char*>(&clientHello);
  txClientHelloRecord.hdr.length = sizeof(clientHello); 
  this->send(txClientHelloRecord);

  //Client receives the ServerHello packet and server's certificate packets 
  Record rxServerCertificateRecord;
  this->recv(&rxServerCertificateRecord);
  const char* rxServerResponse = rxServerCertificateRecord.data;
  
  uint8_t rxServerCertHandshakeType1 = *rxServerResponse;
  uint8_t rxServerCertHandshakeType2 = *(rxServerResponse+1);
  uint8_t rxServerCertHandshakeType3 = *(rxServerResponse+2);
  uint8_t rxServerCertHandshakeType4 = *(rxServerResponse+3);
  uint8_t rxServerCertHandshakeType5 = *(rxServerResponse+4);
  
  if (rxServerCertHandshakeType1 != HS_SERVER_HELLO) {
          cerr << "Server has not sent ServerHello" << endl;
          return -1;
  }
  
  if (rxServerCertHandshakeType2 != HS_CERTIFICATE) {
          cerr << "Server has not sent its certificate" << endl;
          return -1;
  }
 
  if (rxServerCertHandshakeType3 != HS_SERVER_KEY_EXCHANGE) {
          cerr << "Server has not sent its public key" << endl;
          return -1;
  }

  if (rxServerCertHandshakeType4 != HS_CERTIFICATE_REQUEST) {
          cerr << "Server has not requested for client certificate " << endl;
          return -1;
  }
  
  if (rxServerCertHandshakeType5 != HS_SERVER_HELLO_DONE) {
          cerr << "Server has not sent ServerHelloDone" << endl;
          return -1;
  }

  //Client decoding server's certificate information to extract the public-key
  
  if (cxntype == KE_DHE) { 
    this->logger_->log_raw("DHE Key");
    const char* certificateData = rxServerResponse + 5;
    const uint16_t certificateLength = rxServerCertificateRecord.hdr.length - 5;
	string certificate_dhe_str;
	certificate_dhe_str.resize(certificateLength);
	memcpy(&certificate_dhe_str[0],certificateData,rxServerCertificateRecord.hdr.length);
	certificate_dhe_str[certificateLength] = '\0';

	//client extracts and decodes the server's public key, and ephemeral parameters in DHE using BER Decode
	string public_key_encoded, p_dhe_encoded, g_dhe_encoded;
	size_t length_key = certificate_dhe_str.find("\n|\n");
	size_t length_p = certificate_dhe_str.find("\n|\n",length_key+1);
	size_t p_dhe_length = length_p-length_key-3;
	size_t g_dhe_length = certificateLength-length_p-3;
	public_key_encoded.resize(length_key);
	p_dhe_encoded.resize(p_dhe_length);
	g_dhe_encoded.resize(g_dhe_length);
	public_key_encoded = certificate_dhe_str.substr(0,length_key);
	p_dhe_encoded = certificate_dhe_str.substr(length_key+3,p_dhe_length);
	g_dhe_encoded = certificate_dhe_str.substr(length_p+3,g_dhe_length);
	public_key_encoded[length_key] = '\0';
	p_dhe_encoded[p_dhe_length] = '\0';
	g_dhe_encoded[g_dhe_length] = '\0';
    CryptoPP::StringSource public_key_source(public_key_encoded, true);
    CryptoPP::StringSource p_dhe_source(p_dhe_encoded, true);
    CryptoPP::StringSource g_dhe_source(g_dhe_encoded, true);
	CryptoPP::Integer serverPublicKeyDHE;
	CryptoPP::Integer pDHE;
	CryptoPP::Integer gDHE;
	serverPublicKeyDHE.BERDecode(public_key_source); 
	pDHE.BERDecode(p_dhe_source);
	gDHE.BERDecode(g_dhe_source);
	
	CryptoPP::Integer privateKeyDHE;
	CryptoPP::AutoSeededRandomPool rng;
    privateKeyDHE.Randomize(rng, CryptoPP::Integer::One(), CryptoPP::Integer::Power2(2048));
	CryptoPP::Integer publicKeyDHE;
	//client generates its public key 
    publicKeyDHE = a_exp_b_mod_c(gDHE, privateKeyDHE, pDHE);

	string client_public_key_str;
    CryptoPP::StringSink client_public_key_ss(client_public_key_str);
	publicKeyDHE.DEREncode(client_public_key_ss);
	
	struct preMasterBundle_DHE_struct {
			uint8_t handshakeType1;
			uint8_t handshakeType2;
			uint8_t handshakeType3;
			string client_public_key_str;
	};
	
	preMasterBundle_DHE_struct preMasterBundleDHE;
	preMasterBundleDHE.handshakeType1 = HS_CERTIFICATE;
	preMasterBundleDHE.handshakeType2 = HS_CLIENT_KEY_EXCHANGE;
	preMasterBundleDHE.handshakeType3 = HS_CERTIFICATE_VERIFY;
	preMasterBundleDHE.client_public_key_str = client_public_key_str;
	
	stringstream serializedData_DHE;
	serializedData_DHE << hex << preMasterBundleDHE.handshakeType1;
	serializedData_DHE << hex << static_cast<int>(preMasterBundleDHE.handshakeType2);
	serializedData_DHE << hex << preMasterBundleDHE.handshakeType3;
	serializedData_DHE << preMasterBundleDHE.client_public_key_str;
	string serializedDHEData = serializedData_DHE.str();

	//Client sends its public key along wiht its certificates to the server
	Record txPreMasterBundleDHERecord;
    txPreMasterBundleDHERecord.hdr.type = REC_HANDSHAKE;
    txPreMasterBundleDHERecord.hdr.version = VER_99;
    txPreMasterBundleDHERecord.hdr.length = serializedDHEData.length();
    txPreMasterBundleDHERecord.data = const_cast<char*>(serializedDHEData.data());
    this->send(txPreMasterBundleDHERecord);

	//Client generates pre-master secret	
	CryptoPP::Integer clientPreMasterSharedKey;
	clientPreMasterSharedKey = a_exp_b_mod_c(serverPublicKeyDHE, privateKeyDHE, pDHE); 
	stringstream PreMasterSharedKey_ss;
	PreMasterSharedKey_ss << hex << clientPreMasterSharedKey;
    string PreMasterSharedKeyStr = PreMasterSharedKey_ss.str();
	//cout << "Client generates DHE premaster key as " << PreMasterSharedKeyStr << endl;

    const size_t shared_key_length = 16; 

    const size_t salt_length = 0; 
    const size_t info_length = 0; 

    //Client performs session key derivation using HKDF
    byte client_session_keys_DHE[shared_key_length]; 
	CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(client_session_keys_DHE, sizeof(client_session_keys_DHE), reinterpret_cast<const byte*>(PreMasterSharedKeyStr.data()), PreMasterSharedKeyStr.length(), nullptr, salt_length, nullptr, info_length);

    //Client sets the shared session key 
	this->set_shared_key(client_session_keys_DHE,shared_key_length);
	
	//extra logic to convert master key from byte to string for display purpose only
	//stringstream CsessionKey_ss;
	//string CsessionKey_str;
	//for (size_t i = 0 ; i < shared_key_length ; i++) {
	//	CsessionKey_ss << hex << static_cast<int>(client_session_keys_DHE[i]);
	//}
	//CsessionKey_str = CsessionKey_ss.str();
	//cout << "Client generates DHE master key as " << CsessionKey_str << endl;



  }


  if (cxntype == KE_RSA) {

    this->logger_->log_raw("RSA Key");
	//Client generates random value for pre-master key
	CryptoPP::AutoSeededRandomPool rng;
	byte preMasterSecret[20]; //160 bits 
	rng.GenerateBlock(preMasterSecret, sizeof(preMasterSecret));
	std::string preMasterSecretString(reinterpret_cast<const char*>(preMasterSecret), sizeof(preMasterSecret));

	//extra logic only for printing premaster key
	//stringstream preMasterSecret_ss;
	//for (size_t i = 0 ; i < 20; i++) {
	//		preMasterSecret_ss << hex << static_cast<int>(preMasterSecret[i]);
	//}
	//string preMasterSecret_str = preMasterSecret_ss.str();
	//cout << "Client generates RSA premaster key as " << preMasterSecret_str << endl;
	
	//Client extracts the server's certificate information to get its public key to encode pre-master key
	const char* certificateData = rxServerResponse+5;
	const uint16_t certificateLength = rxServerCertificateRecord.hdr.length;
	string certificate;
	certificate.resize(certificateLength);
	memcpy(&certificate[0],certificateData,rxServerCertificateRecord.hdr.length);
	certificate[certificateLength] = '\0';
	
	CryptoPP::RSA::PublicKey public_key_;
	CryptoPP::StringSource certificate_source(certificate, true);
	public_key_.Load(certificate_source);
	
	std::string encryptedpreMasterSecret;
	//Client calls rsa_encrypt function to encrypt the pre-master key with server's public key 
	int result = rsa_encrypt(public_key_, &encryptedpreMasterSecret, preMasterSecretString);
	if (result == 0) {
		//continue as encryption has been successfull	
	} else {
	        std::cerr << "Encryption failed!" << std::endl;
			return -1;
	}
	
	//Client sends the encrypted pre-master key to server along with its certifcates as requested by server
	Record txPreMasterkeyRecord;
	struct premasterkey_struct{
	 uint8_t handshakeType1;
	 uint8_t handshakeType2;
	 uint8_t handshakeType3;
	 string premasterkey;
	};
	
	premasterkey_struct premasterkeyBundle;
	premasterkeyBundle.handshakeType1 = HS_CERTIFICATE;
	premasterkeyBundle.handshakeType2 = HS_CLIENT_KEY_EXCHANGE;
	premasterkeyBundle.handshakeType3 = HS_CERTIFICATE_VERIFY;
	premasterkeyBundle.premasterkey = encryptedpreMasterSecret;
	
	stringstream serial_data_ss;
	serial_data_ss << hex << premasterkeyBundle.handshakeType1;
	serial_data_ss << hex << static_cast<int>(premasterkeyBundle.handshakeType2);
	serial_data_ss << hex << premasterkeyBundle.handshakeType3;
	serial_data_ss << premasterkeyBundle.premasterkey;
	std::string serializedData = serial_data_ss.str();
	
	txPreMasterkeyRecord.hdr.type = REC_HANDSHAKE;
	txPreMasterkeyRecord.hdr.version = VER_99;
	txPreMasterkeyRecord.hdr.length = serializedData.length();
	txPreMasterkeyRecord.data = const_cast<char*>(serializedData.data());
	this->send(txPreMasterkeyRecord);
	
	//Client derives session key using HKDF (HMAC-based Key Derivation Function)
	byte CsessionKey[16];
	CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
	hkdf.DeriveKey(CsessionKey, sizeof(CsessionKey), preMasterSecret, preMasterSecretString.length(), nullptr, 0, nullptr, 0);
	
	//Client sets the session key for further encryption of the data
	this->set_shared_key(CsessionKey, 16);


	//extra logic to convert master key from byte to string for display purpose only
	//stringstream CsessionKey_ss;
	//string CsessionKey_str;
	//for (size_t i = 0 ; i < 16 ; i++) {
	//	CsessionKey_ss << hex << static_cast<int>(CsessionKey[i]);
	//}
	//CsessionKey_str = CsessionKey_ss.str();
	//cout << "Client generates RSA master key as " << CsessionKey_str << endl;
  }

  //Client sends the finished handshake to close the TLS 
  uint8_t client_finished_handshake = HS_FINISHED;
  Record txClientFinishedRecord;
  txClientFinishedRecord.hdr.type = REC_HANDSHAKE;
  txClientFinishedRecord.hdr.version = VER_99;
  txClientFinishedRecord.hdr.length = sizeof(client_finished_handshake);
  txClientFinishedRecord.data = reinterpret_cast<char*>(&client_finished_handshake);
  this->send(txClientFinishedRecord);

  //Client waits for server to close the TLS handshake 
  Record rxServerFinishedRecord;
  this->recv(&rxServerFinishedRecord);
  uint8_t rxServerHandshakeType = static_cast<int>(*rxServerFinishedRecord.data);
  if (rxServerHandshakeType != HS_FINISHED) {
		  cerr << "Server has not finished the TLS handshake" << endl;
		  return -1;
  }

  //Client has successfully executed the TLS handshake
  return 0;
}

int SslClient::close() {
  int ret_code;
  ret_code = this->tcp_->socket_close();
  return ret_code;
}
