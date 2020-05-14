#include "rsadecrypt.h"


// Body

int main(int argc, char *argv[])
{
    unsigned long i_1 = 11;
    unsigned long i_2 = 23;
    unsigned long i_3 = 187;
    mpz_t plain, d, n, cipher;
    mpz_init(cipher);
    mpz_set_ui(cipher, i_1);
    mpz_init(d);
    mpz_set_ui(d, i_2);
    mpz_init(n);
    mpz_set_ui(n, i_3);
    mpz_init(plain);
    decrypt_rsa(plain, d, n, cipher);
}

void decrypt_rsa(mpz_t plain, mpz_t d, mpz_t n, mpz_t cipher){
    mpz_powm (plain, cipher, d, n);
}