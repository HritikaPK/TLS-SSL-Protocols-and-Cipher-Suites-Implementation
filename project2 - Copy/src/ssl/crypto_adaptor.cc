#include "crypto_adaptor.h"

#include <iostream>

#include "integer.h"
#include "modes.h"
#include "rsa.h"
#include "osrng.h"

using namespace std;
using namespace CryptoPP;

int generate_pqg(Integer &p, Integer &q, Integer &g) {
  // 256*4 bit = 1024 bits
  p = Integer("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
              "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
              "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
              "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
              "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
              "DF1FB2BC2E4A4371");

  q = Integer("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");    

  g = Integer("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
              "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
              "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
              "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
              "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
              "855E6EEB22B3B2E5");

  return 0;
}

int generate_rsa_keys(RSA::PrivateKey &private_key, RSA::PublicKey &public_key) {
  AutoSeededRandomPool rnd;
  RSA::PrivateKey rsa_private_key;
  rsa_private_key.GenerateRandomWithKeySize(rnd, 3072);
  RSA::PublicKey rsa_public_key(rsa_private_key);

  private_key = rsa_private_key;
  public_key = rsa_public_key;

  return 0;
}

int aes_encrypt(const unsigned char* key, size_t key_len,
                std::string *cipher_text, const std::string &plain_text) {

  // https://www.cryptopp.com/wiki/CBC_Mode
  SecByteBlock aes_key(key, key_len);
  byte iv[AES::BLOCKSIZE];
  memset(iv, 0, AES::BLOCKSIZE);

  try {
    CBC_Mode<AES>::Encryption aes_enc;
    aes_enc.SetKeyWithIV(aes_key, aes_key.size(), iv);

    StringSource ss(
      plain_text,
      true,
      new StreamTransformationFilter( aes_enc,
        new StringSink( *cipher_text )
        )
      );
  } catch(const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    return -1;
  }
  return 0;
}

int aes_decrypt(const unsigned char* key, size_t key_len,
                std::string *plain_text, const std::string &cipher_text) {

  SecByteBlock aes_key(key, key_len);
  byte iv[AES::BLOCKSIZE];
  memset(iv, 0, AES::BLOCKSIZE);

  try {
    CBC_Mode<AES>::Decryption aes_dec;
    aes_dec.SetKeyWithIV(aes_key, aes_key.size(), iv);

    StringSource ss(
      cipher_text,
      true, 
      new StreamTransformationFilter( aes_dec,
        new StringSink( *plain_text )
      )
    );
  } catch(const CryptoPP::Exception &e) {
    cout << e.what() << endl;
    return -1;
  }
  return 0;
}

int rsa_encrypt(const RSA::PublicKey &pub_key,
                std::string *cipher_text, const std::string &plain_text) {

  AutoSeededRandomPool rng;

  try {
    RSAES_OAEP_SHA_Encryptor encryptor(pub_key);
    
    StringSource ss1(
      plain_text,
      true,
      new PK_EncryptorFilter(
        rng,
        encryptor,
        new StringSink(*cipher_text)
      )
    );

  } catch(const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    return -1;
  }

  return 0;
}

int rsa_decrypt(const RSA::PrivateKey &priv_key,
                std::string *plain_text, const std::string &cipher_text) {

  AutoSeededRandomPool rng;

  try {
    RSAES_OAEP_SHA_Decryptor decryptor(priv_key);

    StringSource ss(
      cipher_text,
      true,
      new PK_DecryptorFilter(
        rng,
        decryptor,
        new StringSink(*plain_text)
      )
    );

  } catch(const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    return -1;
  }

  return 0;
}
