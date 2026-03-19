#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include <iostream>
using namespace std;

void handleErrors() {
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {

  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  // Create and initialise the context 
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  // Initialise the encryption operation. 
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) handleErrors();

  // Provide the message to be encrypted, and obtain the encrypted output.
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
  ciphertext_len = len;

  // Finalise the encryption. Further ciphertext bytes may be written at this stage.
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {

  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  // Create and initialise the context 
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  // Initialise the decryption operation.
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) handleErrors();

  // Provide the message to be decrypted, and obtain the plaintext output.
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
  plaintext_len = len;

  // Finalise the decryption. Further plaintext bytes may be written at this stage.
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int main() {

  // prepare key and IV
  unsigned char key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
					      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
  unsigned char iv[] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
					     0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

  // Message to be encrypted */
  unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";

  // Buffer for ciphertext and decrypted text
  unsigned char ciphertext[128];
  unsigned char decryptedtext[128];
  int decryptedtext_len, ciphertext_len;

  // Encrypt the plaintext 
  ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv, ciphertext);

  // Do something useful with the ciphertext here 
  cout << "Ciphertext is:\n";
  for (int i=0; i<ciphertext_len; i++)
	cout << hex << (int)ciphertext[i];
  cout << endl;
  
  // Decrypt the ciphertext 
  decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

  // Add a NULL terminator. We are expecting printable text 
  decryptedtext[decryptedtext_len] = '\0';

  // Show the decrypted text 
  cout << "Decrypted text is:\n" << decryptedtext << endl;

  return 0;
}

