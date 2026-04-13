// Block_Crypt_2.cxx
// Symmetric encryption with block cipher: 3DES-CFB
// Compile: g++ -Wall -o Block_Crypt_2 Block_Crypt_2.cxx -lcrypto

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
  if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3_cfb64(), NULL, key, iv)) 
  {
    handleErrors();
  }

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) 
  {
    handleErrors();
  }
  ciphertext_len = len;


  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
  {
    handleErrors();
  } 
  ciphertext_len += len;


  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int main(int argc, char *argv[]) 
{

  if (argc != 4) 
  {
    cout << "Usage: ./Block_Crypt_2 key iv inputfile" << endl;
    return 1;
  }

  //prepare key and IV from hex command line args
  unsigned char key[24];  //3DES = 24 bytes (192 bits)
  unsigned char iv[8];    //DES block size = 8 bytes

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
  memset(key, 0, 24);
  memset(iv, 0, 8);
  memcpy(key, key_buf, (key_len < 24) ? key_len : 24);
  memcpy(iv, iv_buf, (iv_len < 8) ? iv_len : 8);

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

  // read entire input file into buffer
  infile.seekg(0, ios::end);
  int filesize = infile.tellg();

  infile.seekg(0, ios::beg);

  unsigned char *plaintext = new unsigned char[filesize];
  infile.read((char *)plaintext, filesize);
  infile.close();


  //buffer for ciphertext
  unsigned char *ciphertext = new unsigned char[filesize + EVP_MAX_BLOCK_LENGTH];
  int ciphertext_len;

  // time onlyencryption
  auto start = chrono::high_resolution_clock::now();

  ciphertext_len = encrypt(plaintext, filesize, key, iv, ciphertext);

  auto end = chrono::high_resolution_clock::now();
  auto duration = chrono::duration_cast<chrono::microseconds>(end - start);

  //create output filename with .enc extension
  string outfile = inputfile;
  size_t dot = outfile.rfind('.');
  if (dot != string::npos)
  {
    outfile = outfile.substr(0, dot); 
  }
    
  outfile += ".enc";

  //write ciphertext to output file
  ofstream encfile(outfile.c_str(), ios::binary);
  encfile.write((char *)ciphertext, ciphertext_len);
  encfile.close();

  cout << "Algorithm: 3DES-CFB" << endl;
  cout << "Input file: " << inputfile << " (" << filesize << " bytes)" << endl;
  cout << "Output file: " << outfile << " (" << ciphertext_len << " bytes)" << endl;
  cout << "Encryption time: " << duration.count() << " microseconds" << endl;

  //clean
  delete[] plaintext;
  delete[] ciphertext;

  return 0;
}