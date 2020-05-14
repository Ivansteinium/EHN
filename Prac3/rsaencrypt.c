#include "rsaencrypt.h"


// Body

int main(int argc, char *argv[])
{
    unsigned long i_1 = 88;
    unsigned long i_2 = 7;
    unsigned long i_3 = 187;
    mpz_t plain, e, n, cipher;
    mpz_init(plain);
    mpz_set_ui(plain, i_1);
    mpz_init(e);
    mpz_set_ui(e, i_2);
    mpz_init(n);
    mpz_set_ui(n, i_3);
    mpz_init(cipher);
    encrypt_rsa(plain, e, n, cipher);
}

void encrypt_rsa(mpz_t plain, mpz_t e, mpz_t n, mpz_t cipher){
    mpz_powm (cipher, plain, e, n);
}