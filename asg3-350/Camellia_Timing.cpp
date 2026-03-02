//Camellia_Timing.cpp
// Brandon Zettek, Yusuf Oner, Jacob Doose, Mohammad Khan
#include <iostream>
#include <ctime>
#include <cstdlib>
#include <openssl/camellia.h>

using namespace std;

int main() 
{
    // prepare Camellia key 
    CAMELLIA_KEY key;
    unsigned char keyBytes[] = { 0x01, 0x22, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };	

    Camellia_set_key(keyBytes, 128, &key); //matches DES

    // example input block: 16 bytes of data
    unsigned char *plaintext = (unsigned char *)"Group 2! Camilla";	
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
        Camellia_ecb_encrypt(plaintext, ciphertext, &key, CAMELLIA_ENCRYPT);

        clock_gettime(CLOCK_REALTIME, &stop); //time right after encryption

        //for nanosec conversion
        long start_time = start.tv_sec * 1000000000 + start.tv_nsec; 
        long stop_time = stop.tv_sec * 1000000000 + stop.tv_nsec;
        all += stop_time - start_time; //running total
    }

    cout << "Average time used for Camellia encryption: " << (all/count) << " nanoseconds" << endl;

    all = 0; //reset for decryption timing

    for (int i = 0; i < count; i++) 
    {
        clock_gettime(CLOCK_REALTIME, &start); //b4 encryption

        // run descryption
        Camellia_ecb_encrypt(ciphertext, deciphertext, &key, CAMELLIA_DECRYPT);
        // check for correctness
        deciphertext[16] = '\0';

        //Test Output that decipher worked
        //cout << "Test out: " << deciphertext << endl;

        clock_gettime(CLOCK_REALTIME, &stop); //time right after encryption

        //for nanosec conversion
        long start_time = start.tv_sec * 1000000000 + start.tv_nsec; 
        long stop_time = stop.tv_sec * 1000000000 + stop.tv_nsec;
        all += stop_time - start_time; //running total
    }

    cout << "Average time used for Camellia decryption: " << (all/count) << " nanoseconds" << endl;

    return 0;
}