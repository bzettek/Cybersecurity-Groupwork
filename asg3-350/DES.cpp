//DES_Timing.cpp
// Brandon Zettek, Yusuf Oner, Jacob Doose, Mohammad Khan
#include <iostream>
#include <ctime>
#include <cstdlib>
#include <openssl/des.h>//will work on linux only if testing on other system

using namespace std;

int main() 
{
    // prepare DES key //1 bit per byte unused, 56 bits total
    DES_cblock cbc_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    DES_key_schedule key;
    DES_set_key(&cbc_key, &key);

    // example input block: 8 bytes of data
    DES_cblock plaintext = {'g', 'r', 'o', 'u', 'p', '2', '!', '!'};

    // block to hold encrypted data
    DES_cblock cyphertext;

    // timing
    long all = 0;
    int count = 1000; //how many times we encrypt
    timespec start, stop; //for before and after encryption

    for (int i = 0; i < count; i++) 
    {
        clock_gettime(CLOCK_REALTIME, &start); //b4 encryption

        // run encryption
        DES_ecb_encrypt(&plaintext, &cyphertext, &key, DES_ENCRYPT);

        clock_gettime(CLOCK_REALTIME, &stop); //time right after encryption

        //for nanosec conversion
        long start_time = start.tv_sec * 1000000000 + start.tv_nsec; 
        long stop_time = stop.tv_sec * 1000000000 + stop.tv_nsec;
        all += stop_time - start_time; //running total
    }

    cout << "Average time used for DES encryption: " << (all/count) << " nanoseconds" << endl;

    return 0;
}