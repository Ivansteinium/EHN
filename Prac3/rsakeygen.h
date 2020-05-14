#ifndef EHN_PRAC3_RSAKEYGEN_H
#define EHN_PRAC3_RSAKEYGEN_H

#include "prac3.h"
#include <gmp.h>
#include "rc4.h"

struct rc4info_t RC4_RNG;

/// The RSA struct to store all the key values
struct rsactx_t
{
    mpz_t e, d, n;
    mpz_t p, q;
    unsigned char seed[16];
};

// Body
/// Sets the RNG seed parameter of rsa struct
/// \param rsa_k Pointer to the main RSA struct
/// \param same_key Boolean check if the default provided key will be used
void setseed(struct rsactx_t *rsa_k, int same_key); // The initial value of the RNG

/// Gets the next prime from a randomly generated value from RC4 RNG
/// \param rsa_k Pointer to the main RSA struct
/// \param p The prime value output
/// \param num_bits the length of the prime number in bits
void getprime(struct rsactx_t *rsa_k, mpz_t p, int num_bits); // get a prime p of num_bits

/// Create the RSA key pair
/// \param rsa_k Pointer to the main RSA struct
/// \param key_len The length of the key that needs to be encrypted in bits
/// \param e_selection Which common value for e will be chosen
void getkeys(struct rsactx_t *rsa_k, int key_len, int e_selection); // fill the rsa struct with the key values.

// Convert hex to int, done because the system hex converter is unreliable
int hex_convert(char hex_string[], int length);

// Print a c-string up to a certain length in hex
void print_hex_string(unsigned char hex_string[], int message_len);


#endif //EHN_PRAC3_RSAKEYGEN_H

