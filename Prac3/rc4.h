#ifndef EHN_PRAC3_RC4_H
#define EHN_PRAC3_RC4_H

#include "prac3.h"
#define U8 unsigned char

// Body
struct rc4ctx_t {
    int S[256];
    int T[256];
    int K[256];
    int idx_1;
    int idx_2;
//    int keylen;
}; // Storing RC4 context

void rc4_init(struct rc4ctx_t* rc4c, U8* key, int keylen); // Initialize rc4
void swap(int* S, int idx_1, int idx_2); // Swap 2 values in S array
U8 rc4_getbyte(struct rc4ctx_t* rc4c); // Retrive byte to xor

#endif //EHN_PRAC3_RC4_H

