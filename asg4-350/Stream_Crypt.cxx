#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <time.h>  

void hex_to_bytes(const char *hex, unsigned char *bytes, int len) 
{
    for (int i = 0; i < len; i++) 
    {
        sscanf(hex + 2*i, "%2hhx", &bytes[i]);
    }
}

int main(int argc, char *argv[]) 
{
    if (argc != 3) 
    {
        printf("Usage: %s key inputfile\n", argv[0]);
        return 1;
    }

    char *hexkey = argv[1];
    char *inputfile = argv[2];

    unsigned char key[16];
    hex_to_bytes(hexkey, key, 16);

    FILE *in = fopen(inputfile, "rb");
    if (!in) 
    {
        printf("Error opening input file\n");
        return 1;
    }

    char outputfile[256];
    snprintf(outputfile, sizeof(outputfile), "%s.enc", inputfile);

    FILE *out = fopen(outputfile, "wb");
    if (!out) 
    {
        printf("Error opening output file\n");
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL);

    unsigned char inbuf[1024], outbuf[1024];
    int inlen, outlen;
    long total_bytes = 0;

    // START TIMING
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) 
    {
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, out);
        total_bytes += inlen;
    }

    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, out);

    // STOP TIMING
    clock_gettime(CLOCK_MONOTONIC, &end);
    long elapsed_us = (end.tv_sec - start.tv_sec) * 1000000L
                    + (end.tv_nsec - start.tv_nsec) / 1000L;

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    printf("Algorithm: RC4\n");
    printf("Input file: %s (%ld bytes)\n", inputfile, total_bytes);
    printf("Output file: %s\n", outputfile);
    printf("Encryption time: %ld microseconds\n", elapsed_us);

    return 0;
}
