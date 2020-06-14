#ifndef EHN_PRAC3_RSAKEYGEN_H
#define EHN_PRAC3_RSAKEYGEN_H

#include "prac3.h"

struct rc4ctx_t rc4ctx;


/**
 * Gets the next prime from a randomly generated value from RC4 RNG.
 * @param prime The prime value output.
 * @param num_bits The length of the prime number in bits.
 */
void getprime(mpz_t prime, int num_bits);


/**
 * Create the RSA key pair.
 * @param rsactx Pointer to the main RSA struct.
 * @param key_len The length of the key that needs to be encrypted in bits.
 * @param e_selection Which common value for e will be chosen.
 */
void getkeys(struct rsactx_t *rsactx, int key_len, int e_selection);


#endif // EHN_PRAC3_RSAKEYGEN_H
