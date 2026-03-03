//AES_Timing.cpp
// Brandon Zettek, Yusuf Oner, Jacob Doose, Mohammad Khan
#include <iostream>
#include <ctime>
#include <cstdlib>
#include <openssl/aes.h>

using namespace std;

int main() 
{
    // prepare AES key
    AES_KEY key;
    unsigned char keyBytes[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

    AES_set_encrypt_key(keyBytes, 128, &key);

    // example input block: 16 bytes of data
    unsigned char *plaintext = (unsigned char *)"Group 2! AES!!!";

    // buffer to hold encrypted data
    unsigned char ciphertext[16];

    // timing
    long all = 0;
    int count = 1000; //how many times we encrypt
    timespec start, stop; //for before and after encryption

    // buffer to hold decrypted data
    unsigned char deciphertext[17];

    for (int i = 0; i < count; i++) 
    {
        clock_gettime(CLOCK_REALTIME, &start); //b4 encryption

        // run encryption
        AES_ecb_encrypt(plaintext, ciphertext, &key, AES_ENCRYPT);

        clock_gettime(CLOCK_REALTIME, &stop); //time right after encryption

        //for nanosec conversion
        long start_time = start.tv_sec * 1000000000 + start.tv_nsec; 
        long stop_time = stop.tv_sec * 1000000000 + stop.tv_nsec;
        all += stop_time - start_time; //running total
    }

    cout << "Average time used for AES encryption: " << (all/count) << " nanoseconds" << endl;

    all = 0; //reset for decryption timing

    AES_set_decrypt_key(keyBytes, 128, &key);

    for (int i = 0; i < count; i++) 
    {
        clock_gettime(CLOCK_REALTIME, &start); //b4 encryption

        // run decryption
        AES_ecb_encrypt(ciphertext, deciphertext, &key, AES_DECRYPT);
        clock_gettime(CLOCK_REALTIME, &stop); //time right after encryption

        //for nanosec conversion
        long start_time = start.tv_sec * 1000000000 + start.tv_nsec; 
        long stop_time = stop.tv_sec * 1000000000 + stop.tv_nsec;
        all += stop_time - start_time; //running total
    }

    cout << "Average time used for AES decryption: " << (all/count) << " nanoseconds" << endl;

    return 0;
}