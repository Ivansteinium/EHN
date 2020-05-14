#ifndef EHN_PRAC3_RSADECRYPT_H
#define EHN_PRAC3_RSADECRYPT_H

#include "prac3.h"
#include <gmp.h>

// Body
void decrypt_rsa(mpz_t plain, mpz_t d, mpz_t n, mpz_t cipher);

#endif //EHN_PRAC3_RSADECRYPT_H

