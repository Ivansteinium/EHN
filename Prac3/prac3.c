#include "prac3.h"


// Simply swap two values by reference
void swap(int *a, int *b)
{
    int temp;
    temp = *a;
    *a = *b;
    *b = temp;
}

// Set up the RC4 cipher as done in "Network Security Essentials", William stallings, page 48
void rc4_init(struct rc4info_t *rc4i, unsigned char *key, int keylen)
{
    int i;
    int T[255];
    for (i = 0; i < 256; i++) // Initialise values
    {
        rc4i->S[i] = i;
        T[i] = key[i % keylen];
    }

    int j = 0;
    for (i = 0; i < 256; i++) // Do the initial permutation of S
    {
        j = (j + rc4i->S[i] + T[i]) % 256;
        swap(&(rc4i->S[i]), &(rc4i->S[j]));
    }

    rc4i->i = 0; // Set up permutation variables in the struct
    rc4i->j = 0;
}

// Generate a byte using the RC4 cipher as done in "Network Security Essentials", William stallings, page 48
unsigned char rc4_getbyte(struct rc4info_t *rc4i)
{
    // Increment the swap indexes
    rc4i->i = (rc4i->i + 1) % 256;
    rc4i->j = (rc4i->j + rc4i->S[rc4i->i]) % 256;

    // Swap the values in the S array
    swap(&(rc4i->S[rc4i->i]), &(rc4i->S[rc4i->j]));

    // Sum the swapped values
    int t = (rc4i->S[rc4i->i] + rc4i->S[rc4i->j]) % 256;
    return rc4i->S[t];
}


// Print a c-string up to a certain length in hex
void print_hex_string(unsigned char hex_string[], int message_len)
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