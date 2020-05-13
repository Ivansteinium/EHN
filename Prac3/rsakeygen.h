#ifndef EHN_PRAC3_RSAKEYGEN_H
#define EHN_PRAC3_RSAKEYGEN_H

#include "prac3.h"
#include <gmp.h>
#include "rc4.h"

struct rc4info_t RC4_RNG;

struct rsactx_t
{
    mpz_t e, d, n;
    mpz_t p, q;
    unsigned char seed[16];
};

// Body
void setseed(struct rsactx_t *rsa_k, int same_key); // The initial value of the RNG
void getprime(struct rsactx_t *rsa_k, mpz_t p, int num_bits); // get a prime p of num_bits


#endif //EHN_PRAC3_RSAKEYGEN_H

