#include "prac3.h"


// RC4 functions
// Set up the RC4 cipher as done in "Network Security Essentials", William stallings, page 48
void rc4_init(struct rc4ctx_t *rc4ctx, U8 key[], int keylen)
{
    int i;
    int T[256];

    for (i = 0; i < 256; i++) // Initialise values
    {
        rc4ctx->S[i] = i;
        T[i] = key[i % keylen];
    }

    int j = 0;
    for (i = 0; i < 256; i++) // Do the initial permutation of S
    {
        j = (j + rc4ctx->S[i] + T[i]) % 256;
        swap(&(rc4ctx->S[i]), &(rc4ctx->S[j]));
    }

    rc4ctx->i = 0; // Set up permutation variables in the struct
    rc4ctx->j = 0;
}


// Generate a byte using the RC4 cipher as done in "Network Security Essentials", William stallings, page 48
U8 rc4_getbyte(struct rc4ctx_t *rc4ctx)
{
    // Increment the swap indexes
    rc4ctx->i = (rc4ctx->i + 1) % 256;
    rc4ctx->j = (rc4ctx->j + rc4ctx->S[rc4ctx->i]) % 256;

    // Swap the values in the S array
    swap(&(rc4ctx->S[rc4ctx->i]), &(rc4ctx->S[rc4ctx->j]));

    // Sum the swapped values
    int t = (rc4ctx->S[rc4ctx->i] + rc4ctx->S[rc4ctx->j]) % 256;
    return rc4ctx->S[t];
}


// RSA functions
// Initialises the RSA context
void rsa_init(struct rsactx_t *rsactx)
{
    mpz_init(rsactx->d);
    mpz_init(rsactx->e);
    mpz_init(rsactx->n);
    mpz_init(rsactx->p);
    mpz_init(rsactx->q);
}


// Frees the memory associated with the RSA context.
void rsa_clean(struct rsactx_t *rsactx)
{
    mpz_clear(rsactx->d);
    mpz_clear(rsactx->e);
    mpz_clear(rsactx->n);
    mpz_clear(rsactx->p);
    mpz_clear(rsactx->q);
}


// Common functions
// Simply swap two values by reference
void swap(int *a, int *b)
{
    int temp;
    temp = *a;
    *a = *b;
    *b = temp;
}


// Print a c-string up to a certain length in hex
void print_hex_string(U8 hex_string[], int message_len)
{
    int i;
    for (i = 0; i < message_len; i++)
        printf("%02X", hex_string[i]);
}


// Convert hex to int, done because the system hex converter is unreliable
int hex_convert(char hex_string[], int length)
{
    int result = 0;
    int base = 1;

    int i;
    for (i = length; i > 0; i--)
    {
        switch (hex_string[i - 1])
        {
            case '0': {break;}
            case '1': {result += base * 1; break;}
            case '2': {result += base * 2; break;}
            case '3': {result += base * 3; break;}
            case '4': {result += base * 4; break;}
            case '5': {result += base * 5; break;}
            case '6': {result += base * 6; break;}
            case '7': {result += base * 7; break;}
            case '8': {result += base * 8; break;}
            case '9': {result += base * 9; break;}
            case 'A': {result += base * 10; break;}
            case 'B': {result += base * 11; break;}
            case 'C': {result += base * 12; break;}
            case 'D': {result += base * 13; break;}
            case 'E': {result += base * 14; break;}
            case 'F': {result += base * 15; break;}
            case 'a': {result += base * 10; break;}
            case 'b': {result += base * 11; break;}
            case 'c': {result += base * 12; break;}
            case 'd': {result += base * 13; break;}
            case 'e': {result += base * 14; break;}
            case 'f': {result += base * 15; break;}
            default:
            {
                printf("The input given (\'%c\') is not a valid HEX character\nTerminating...\n", hex_string[i]);
                exit(EXIT_FAILURE);
            }
        }

        base *= 16;
    }

    return result;
}