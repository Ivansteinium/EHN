#include <obstack.h>
#include "rsakeygen.h"


// Body
int main(int argc, char *argv[])
{
    struct rsactx_t rsa;
    setseed(&rsa, 1);
    rc4_init(&RC4_RNG, rsa.seed, 8);
    mpz_t large_prime;
    mpz_init(large_prime);
    //getprime(&rsa, large_prime, 15);
    getkeys(&rsa, 256, 2);

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

void getkeys(struct rsactx_t *rsa_k, int key_len, int e_selection){
    mpz_t phi;
    mpz_t p_1, q_1, val_1;
    mpz_t phi_1;
    mpz_t remain;
    unsigned long i_1 = 1;
    int p_q_bit_len = (key_len)/2;
    unsigned long e[3] = {3, 17, 65537};
//    mpz_init(rsa_k->p);
//    mpz_init(rsa_k->q);
//    mpz_init(rsa_k->n);
//    mpz_init(p_1);
//    mpz_init(q_1);
//    mpz_init_set_ui (rsa_k->e, e[e_selection]);
//    mpz_init_set_ui (val_1, i_1);
//    mpz_init(phi);
//    mpz_init(phi_1);
//    mpz_init(rsa_k->d);
//    mpz_init(remain);

    do {
//        mpz_clear(rsa_k->p);
//        mpz_clear(rsa_k->q);
//        mpz_clear(rsa_k->n);
//        mpz_clear(p_1);
//        mpz_clear(q_1);
//        mpz_clear(rsa_k->e);
//        mpz_clear(val_1);
//        mpz_clear(phi);
//        mpz_clear(phi_1);
//        mpz_clear(rsa_k->d);
//        mpz_clear(remain);

        do {
            mpz_init(rsa_k->p);
            getprime(rsa_k, rsa_k->p, p_q_bit_len);

            mpz_init(rsa_k->q);
            getprime(rsa_k, rsa_k->q, p_q_bit_len); // Random prime p and q
        } while (mpz_get_ui(rsa_k->p) == mpz_get_ui(rsa_k->q)); // p != q

        mpz_init(rsa_k->n);
        mpz_mul(rsa_k->n, rsa_k->p, rsa_k->q); // Set n

        mpz_init_set_ui (rsa_k->e, e[e_selection]); //set e from common e values

        mpz_init_set_ui (val_1, i_1); // Create a mpz struct with val 1 for subtraction.
        mpz_init(p_1);
        mpz_sub(p_1, rsa_k->p, val_1); // (p-1)

        mpz_init(q_1);
        mpz_sub(q_1, rsa_k->q, val_1); // (q-1)

        mpz_init(phi);
        mpz_mul(phi, p_1, q_1); // phi = (p-1)(q-1)

//    mpz_init(mod_out);
//    mpz_mod (mod_out, rsa_k->e, phi); // e mod phi

        mpz_init(phi_1);
        mpz_add (phi_1, phi, val_1);

        mpz_init(rsa_k->d);
        mpz_init(remain);
        mpz_tdiv_qr(rsa_k->d, remain, phi_1, rsa_k->e);
//        mpz_mod (remain, phi_1, rsa_k->d);
    } while ((mpz_get_ui(remain) != 0) || (mpz_cmp(rsa_k->d, phi) >= 0));

    mpz_out_str(stdout, 10, phi_1);
    printf("\n");
    mpz_out_str(stdout, 10, rsa_k->d);
    printf("\n");
    printf("phi: %lu\n", mpz_get_ui(phi_1));
    printf("d: %lu\n", mpz_get_ui(rsa_k->d));
    unsigned long temp = 14851388866727294549;
    int x = temp % 65537;
}