#ifndef EHN_PRAC3_RSADECRYPT_H
#define EHN_PRAC3_RSADECRYPT_H

#include "prac3.h"


/**
 * Uses the GMP power function to decrypt a mpz_t value.
 * @param plain The output of the decrypt operation.
 * @param d The secret exponent.
 * @param n The modulus.
 * @param cipher The value to be decrypted.
 */
void decrypt_rsa(mpz_t plain, mpz_t d, mpz_t n, mpz_t cipher);


#endif // EHN_PRAC3_RSADECRYPT_H
