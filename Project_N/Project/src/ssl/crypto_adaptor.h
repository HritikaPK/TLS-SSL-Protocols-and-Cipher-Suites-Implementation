#ifndef CRYPTO_ADAPTOR_H
#define CRYPTO_ADAPTOR_H

#include "string.h"

#include "integer.h"
#include "rsa.h"

//////////////////////////////////////////////
// DHE
int generate_pqg(CryptoPP::Integer &p, CryptoPP::Integer &q, CryptoPP::Integer &g);

//////////////////////////////////////////////
// RSA
int generate_rsa_keys(CryptoPP::RSA::PrivateKey &private_key, CryptoPP::RSA::PublicKey &public_key);

//////////////////////////////////////////////
// Encryption
int aes_encrypt(const unsigned char* key, size_t key_len,
                std::string *cipher_text, const std::string &plain_text);

int aes_decrypt(const unsigned char* key, size_t key_len,
                std::string *plain_text, const std::string &cipher_text);

int rsa_encrypt(const CryptoPP::RSA::PublicKey &pub_key,
                std::string *cipher_text, const std::string &plain_text);

int rsa_decrypt(const CryptoPP::RSA::PrivateKey &priv_key,
                std::string *plain_text, const std::string &cipher_text);



#endif // CRYPTO_ADAPTOR_H






