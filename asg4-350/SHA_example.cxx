/*
 * SHA_Example.cxx
 * 
 */

#include <openssl/evp.h>
#include <string.h>
#include <iostream>
using namespace std;

int main() {
   // sample input text
   char mess1[] = "Test Message\n";
   char mess2[] = "Hello World\n";
   // hash value
   unsigned char md_value[EVP_MAX_MD_SIZE];
   unsigned int md_len;
   
   // setup and create context
   EVP_MD_CTX *mdctx;
   mdctx = EVP_MD_CTX_create();
   
   // initialize hash function
   EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
   
   // feed data to hash function
   EVP_DigestUpdate(mdctx, mess1, strlen(mess1));
   EVP_DigestUpdate(mdctx, mess2, strlen(mess2));
   
   // get hash value
   EVP_DigestFinal_ex(mdctx, md_value, &md_len);

   cout << "Message digest is: ";
   for(unsigned int i = 0; i < md_len; i++)
  	  cout << hex << (int) md_value[i];
   cout << endl;
   
   // cleanup
   EVP_MD_CTX_destroy(mdctx);	
   return 0;
}

