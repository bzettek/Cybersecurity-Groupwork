/*
 * AES_Timing.cpp
 *
 * Brandon Zettek, Yusuf Oner, Jacob Doose, Mohammad Khan
 */

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <iostream>
#include <ctime>
#include <openssl/aes.h>

using namespace std;

int main() {

    const int LOOPS = 1000000;

    // ------------------ Prepare AES Key ------------------
    AES_KEY key;
    unsigned char keyBytes[16] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef
    };

    // ------------------ Plaintext (exactly 16 bytes) ------------------
    unsigned char plaintext[16] = {
        's','e','c','r','e','t',' ',
        'm','e','s','s','a','g','e',
        '!','!'
    };

    // Buffers
    unsigned char ciphertext[16];
    unsigned char deciphertext[17];

    clock_t start, end;

    // ================= Encryption Timing =================
    AES_set_encrypt_key(keyBytes, 128, &key);

    start = clock();
    for (int i = 0; i < LOOPS; i++) {
        AES_ecb_encrypt(plaintext, ciphertext, &key, AES_ENCRYPT);
    }
    end = clock();

    double enc_time = double(end - start) / CLOCKS_PER_SEC;
    double enc_avg = enc_time / LOOPS;

    // ================= Decryption Timing =================
    AES_set_decrypt_key(keyBytes, 128, &key);

    start = clock();
    for (int i = 0; i < LOOPS; i++) {
        AES_ecb_encrypt(ciphertext, deciphertext, &key, AES_DECRYPT);
    }
    end = clock();

    double dec_time = double(end - start) / CLOCKS_PER_SEC;
    double dec_avg = dec_time / LOOPS;

    // Print Results
    cout << "AES Encryption avg time: " << enc_avg << " seconds" << endl;
    cout << "AES Decryption avg time: " << dec_avg << " seconds" << endl;

    return 0;
}
