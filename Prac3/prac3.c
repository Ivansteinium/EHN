#include "prac3.h"

void swap(int *a, int *b)
{
    int temp;
    temp = *a;
    *a = *b;
    *b = temp;
}

// Body
void rc4_init(struct rc4info_t *rc4i, unsigned char *key, int keylen) // Set up the RC4 cipher as done in "Network
// Security Essentials", William stallings, page 48
{
    int i;
    int T[255];
    for (i = 0; i < 256; i++) // initialise values
    {
        rc4i->S[i] = i;
        T[i] = key[i % keylen];
    }
    int j = 0;
    for (i = 0; i < 256; i++) // do the initial permutation of S
    {
        j = (j + rc4i->S[i] + T[i]) % 256;
        swap(&(rc4i->S[i]), &(rc4i->S[j]));
    }
    rc4i->i = 0; // set up permutation variables in the struct
    rc4i->j = 0;
}

unsigned char rc4_getbyte(struct rc4info_t *rc4i)// Generate a byte using the RC4 cipher as done in "Network
// Security Essentials", William stallings, page 48
{
    // increment the swap indexes
    rc4i->i = (rc4i->i + 1) % 256;
    rc4i->j = (rc4i->j + rc4i->S[rc4i->i]) % 256;
    // swap the values in the S array
    swap(&(rc4i->S[rc4i->i]), &(rc4i->S[rc4i->j]));
    // sum the swapped values
    int t = (rc4i->S[rc4i->i] + rc4i->S[rc4i->j]) % 256;
    return rc4i->S[t];
}