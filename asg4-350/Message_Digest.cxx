#include <openssl/evp.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
using namespace std;
using namespace std::chrono;

int main(int argc, char* argv[]) 
{
   if (argc != 2) 
   {
      cerr << "Usage: ./Message_Digest <inputfile>" << endl;
      return 1;
   }

   // load entire file into memory. using binary prevents differences b/w mac/linux and windows caused by line endings
   ifstream file(argv[1], ios::binary);
   if (!file) {
      cerr << "Error: cannot open file '" << argv[1] << "'" << endl;
      return 1;
   }
   vector<unsigned char> fileData(
      (istreambuf_iterator<char>(file)),
      (istreambuf_iterator<char>())
   );

   // hash value
   unsigned char md_value[EVP_MAX_MD_SIZE];
   unsigned int md_len;

   // setup and create context
   EVP_MD_CTX *mdctx;
   mdctx = EVP_MD_CTX_create();

   // start timing
   auto startTime = high_resolution_clock::now();

   // initialize hash function
   EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

   // feed data to hash function
   EVP_DigestUpdate(mdctx, fileData.data(), fileData.size());

   // get hash value
   EVP_DigestFinal_ex(mdctx, md_value, &md_len);

   // stop timing
   auto endTime = high_resolution_clock::now();

   // report
   cout << "Message digest is: ";
   for (unsigned int i = 0; i < md_len; i++)
      cout << hex << (int) md_value[i];
   cout << endl;

   auto duration = duration_cast<microseconds>(endTime - startTime);
   cout << dec << "File size:    " << fileData.size() << " bytes" << endl;
   cout << "Elapsed time: " << duration.count() << " microseconds" << endl;

   // cleanup
   EVP_MD_CTX_destroy(mdctx);
   return 0;
}