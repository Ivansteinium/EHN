#ifndef EHN_PRAC3_RSAKEYGEN_H
#define EHN_PRAC3_RSAKEYGEN_H

#include "prac3.h"
#include <obstack.h>


struct rc4ctx_t RC4_RNG;


/**
 * Sets the RNG seed parameter of rsa struct.
 * @param rsa_k Pointer to the main RSA struct.
 * @param same_key Boolean check if the default provided key will be used.
 */
void setseed(struct rsactx_t *rsa_k, int same_key);


/**
 * Gets the next prime from a randomly generated value from RC4 RNG.
 * @param rsa_k Pointer to the main RSA struct.
 * @param p The prime value output.
 * @param num_bits The length of the prime number in bits.
 */
void getprime(struct rsactx_t *rsa_k, mpz_t p, int num_bits);


/**
 * Create the RSA key pair.
 * @param rsa_k Pointer to the main RSA struct.
 * @param key_len The length of the key that needs to be encrypted in bits.
 * @param e_selection Which common value for e will be chosen.
 */
void getkeys(struct rsactx_t *rsa_k, int key_len, int e_selection);


#endif // EHN_PRAC3_RSAKEYGEN_H
