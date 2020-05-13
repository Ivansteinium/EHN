#include <obstack.h>
#include "rsakeygen.h"


// Body
int main(int argc, char *argv[])
{
    struct rsactx_t rsa;
    mpz_t large_prime;
    mpz_init(large_prime);
    getprime(&rsa, large_prime, 15);
    int x = 1;
    int num_bits = -1;
    char *private_key_file_name = NULL;
    char *public_key_file_name = NULL;
    int key[16];
    bool args[4] = {false, false, false, false};

    char help_message[] = "rsakeygen -b bits -KU public_key_file -KR private_key_file -key key\n \n"
                          "The bits specify the number of bits that need to be generated for the given key. \n"
                          "The key that will be used to set the RNG (Random Number Generator) seed is specified as "
                          "hexadecimal numbers in the command-line parameters.\n"
                          "The public_key_file is the filename to which the public key should be written. \n"
                          "The private_key_file is the filename to which the private key should be written.\n";
                          // from guide, refine/change if necessary

    if (argc < 8)
    {
        printf("Too few arguments were supplied\n");
        printf("Proper use of the program is as follows:\n \n %s \n",help_message);
        return EXIT_FAILURE;
    }
    int arg;
    for (arg = 1; arg < argc; arg++)
    {
        if (strstr(argv[arg], "-b") != NULL) // Set the number of bits to generate
        {
            args[0] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            int i;
            for (i = 0; i < strlen(argv[arg + 1]); i++)
            {
                if (!isdigit(argv[arg + 1][i]))
                {
                    printf("argument %s is not a valid number.\n", argv[arg + 1]);
                    return EXIT_FAILURE;
                }
            }
            num_bits = (int) strtol(argv[arg + 1], NULL, 10);
            printf("%i bits will be generated\n");
            arg++; // Skip over the value parameter that follows this parameter
        }
        else
        {
            printf("Invalid parameter supplied: %s\n",argv[arg]);
            printf("Proper use of the program is as follows:\n %s \n",help_message);
            return EXIT_FAILURE;
        }
    }
}



void setseed(struct rsactx_t *rsa_k, int same_key){
    if (same_key){
        rsa_k->seed[0] = 0x01;
        rsa_k->seed[1] = 0x23;
        rsa_k->seed[2] = 0x45;
        rsa_k->seed[3] = 0x67;
        rsa_k->seed[4] = 0x89;
        rsa_k->seed[5] = 0xAB;
        rsa_k->seed[6] = 0xCD;
        rsa_k->seed[7] = 0xEF;
    } else {
        // find random value
    }
}

void getprime(struct rsactx_t *rsa_k, mpz_t p, int num_bits){
    unsigned long result = 1;
    mpz_t not_prime;
    int num_rand_bytes = (num_bits-1)/8;
    unsigned int temp;
    int remain = (num_bits-1)%8;
    setseed(rsa_k, 1);
    rc4_init(&RC4_RNG, rsa_k->seed, 8);

    // Loop until right length
    for (int i = 0; i < num_rand_bytes; ++i){
        result = result<<8;
        result = result | rc4_getbyte(&RC4_RNG);
    }

    if (remain>0){
        temp = rc4_getbyte(&RC4_RNG)>>(8-remain);
        result = result<<remain;
        result = result | temp;
    }

    mpz_init_set_ui (not_prime, result);
    mpz_nextprime(p, not_prime);
}