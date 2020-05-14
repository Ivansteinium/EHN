#ifndef EHN_PRAC3_RSAENCRYPT_H
#define EHN_PRAC3_RSAENCRYPT_H

#include "prac3.h"
#include <gmp.h>

// Body

void encrypt_rsa(mpz_t plain, mpz_t e, mpz_t n, mpz_t cipher);

#endif //EHN_PRAC3_RSAENCRYPT_H

