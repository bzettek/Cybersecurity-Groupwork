# CSCI 350 – Applied Cryptography & Network Security Labs

Group 2 — Brandon Zettek, Yusuf Oner, Jacob Doose, Mohammad Khan

Three assignments covering cipher benchmarking, file encryption, and live port scanning against a class server. All written in C/C++ using OpenSSL.

---

## Assignment 3 — Cipher Timing Benchmark

Measures how fast DES, AES-128, and Camellia actually run on the machine. Each program runs encrypt + decrypt 1000 times, averages the nanosecond timings, and prints them out. The point was to see the real-world performance difference between an old 56-bit cipher (DES) and modern ones.

**Files:** `asg3-350/AES_Timing.cpp`, `DES_Timing.cpp`, `Camellia_Timing.cpp`

---

## Assignment 4 — File Encryption & Hashing

A collection of tools for actually encrypting files and generating message digests:

- **Block_Crypt_1 / Block_Crypt_2** — Encrypts a file using AES-128-CBC (EVP API). Takes a key, IV, and input file from the command line, writes a `.enc` output, and reports how long it took in microseconds.
- **Stream_Crypt** — Same idea but with RC4 (stream cipher). Useful for comparing block vs stream cipher speed on the same file.
- **Message_Digest** — SHA-256 hash of any file, with timing. Good for verifying file integrity.
- **EVP_Example / SHA_example** — Smaller standalone examples of the OpenSSL EVP and SHA APIs.

**Files:** `asg4-350/`

---

## Assignment 5 — Port Scanner + RC4 Decryption

The most involved one. Connects to `blitz.cs.niu.edu` (NIU VPN required) and:

1. **UDP scan** ports 9000–9100 — finds the open port, which responds with a 16-byte secret key
2. **TCP scan** ports 9000–9100 — finds the open port, which responds with an RC4-encrypted message
3. **RC4 decrypt** — uses the secret key from step 1 to decrypt the message from step 2 and print it

The RC4 implementation is hand-rolled (KSA + PRGA, XOR-based). The scanner also timestamps each phase and prints a summary at the end.

**Files:** `asg5-350/finalScanner.cxx`, `tcp_example.cxx`, `udp_example.cxx`

---

## Building

All programs link against OpenSSL. General compile pattern:

```bash
g++ -Wall -o <program> <file>.cxx -lcrypto
```

For the port scanner:
```bash
g++ -Wall -o scanner finalScanner.cxx
```

> Note: Assignment 5 requires an active NIU VPN connection to reach the target server.
