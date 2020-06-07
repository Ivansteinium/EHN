#ifndef EHN_PRAC3_RSAENCRYPT_H
#define EHN_PRAC3_RSAENCRYPT_H

#include "prac3.h"


/**
 * Uses the GMP power function to encrypt a mpz_t value.
 * @param plain The value to be encrypted.
 * @param e The public exponent.
 * @param n The modulus.
 * @param cipher The output of the encrypt operation.
 */
void encrypt_rsa(mpz_t plain, mpz_t e, mpz_t n, mpz_t cipher);


#endif // EHN_PRAC3_RSAENCRYPT_H
