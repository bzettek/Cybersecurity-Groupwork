// Block_Crypt_1.cxx
// Symmetric encryption with block cipher: AES-128-CBC
// Compile: g++ -Wall -o Block_Crypt_1 Block_Crypt_1.cxx -lcrypto

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <string.h>

#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
using namespace std;

//from slides
void handleErrors() 
{
  ERR_print_errors_fp(stderr);
  abort();
}

//takes plaintext and plaintext len which is how many bytes
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) 
{


  EVP_CIPHER_CTX *ctx; //pointer to EVP cipher cntxt state object to track
  int len;
  int ciphertext_len;

  //creates cipher context and assing to ctx
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  //initialise  encryption op
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) handleErrors();

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
  ciphertext_len = len;

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  //clean up
  EVP_CIPHER_CTX_free(ctx);


  return ciphertext_len; //gives main amount of bytes
}

int main(int argc, char *argv[]) 
{

  if (argc != 4) 
  {
    cout << "Usage: ./Block_Crypt_1 key iv inputfile" << endl;
    return 1;
  }

  //prepare key and IV from hex command line args
  unsigned char key[16];  //AES-128 = 16 bytes
  unsigned char iv[16];   //AES block size = 16 bytes

  long key_len = 0;
  long iv_len = 0;

  unsigned char *key_buf = OPENSSL_hexstr2buf(argv[1], &key_len);
  unsigned char *iv_buf = OPENSSL_hexstr2buf(argv[2], &iv_len);

  if (!key_buf || !iv_buf) 
  {
    cout << "Error: invalid hex string for key or iv" << endl;
    return 1;
  }

  //copy into fixed-size arrayspad with zeros if needed
  memset(key, 0, 16);
  memset(iv, 0, 16);
  memcpy(key, key_buf, (key_len < 16) ? key_len : 16);
  memcpy(iv, iv_buf, (iv_len < 16) ? iv_len : 16);


  OPENSSL_free(key_buf);
  OPENSSL_free(iv_buf);

  //open read input file
  string inputfile = argv[3];
  ifstream infile(inputfile.c_str(), ios::binary);
  if (!infile) 
  {
    cout << "Error: cannot open input file: " << inputfile << endl;
    return 1;
  }

  infile.seekg(0, ios::end);
  int filesize = infile.tellg();
  infile.seekg(0, ios::beg);

  unsigned char *plaintext = new unsigned char[filesize];
  infile.read((char *)plaintext, filesize);
  infile.close();

  
  //buffer for ciphertext
  unsigned char *ciphertext = new unsigned char[filesize + EVP_MAX_BLOCK_LENGTH];
  int ciphertext_len;

  //time only encryption
  auto start = chrono::high_resolution_clock::now();

  ciphertext_len = encrypt(plaintext, filesize, key, iv, ciphertext);

  auto end = chrono::high_resolution_clock::now();
  auto duration = chrono::duration_cast<chrono::microseconds>(end - start);

  //create output filename with .enc extension
  string outfile = inputfile;
  size_t dot = outfile.rfind('.');
  if (dot != string::npos)
    outfile = outfile.substr(0, dot);
  outfile += ".enc";

  //write ciphertext to output file
  ofstream encfile(outfile.c_str(), ios::binary);
  encfile.write((char *)ciphertext, ciphertext_len);
  encfile.close();


  cout << "Algorithm: AES-128-CBC" << endl;
  cout << "Input file: " << inputfile << " (" << filesize << " bytes)" << endl;
  cout << "Output file: " << outfile << " (" << ciphertext_len << " bytes)" << endl;
  cout << "Encryption time: " << duration.count() << " microseconds" << endl;

  //clean
  delete[] plaintext;
  delete[] ciphertext;

  return 0;
}