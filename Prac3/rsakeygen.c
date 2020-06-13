#include "rsakeygen.h"

/// This utility generates a public/private key pair to be used to encrypt and decrypt the RC4 key.
int main(int argc, char *argv[]) {
    int i;
    int num_bits = -1;
    char *private_key_file_name = NULL;
    char *public_key_file_name = NULL;
    bool args[4] = {false, false, false, false};
    U8 seed[17];
    int seedlen = 0;
    char help_message[] = "\t./rsakeygen -arg1 value1 -arg2 value2...\n"
                          "\t\n"
                          "\tThe following arguments should then be given in this order:\n\n"
                          "\t-bitLen <number of bits>\n"
                          "\t-fopub <public key file>\n"
                          "\t-fopriv <private key file>\n"
                          "\t-init <RC4 RNG string in ASCII> (optional)"
                          "\t\nRemember to add \"double quotes\" if spaces are present in an argument\n"
                          "\t\nExample usage:\n"
                          "\t1.\t./rsakeygen -bitLen 128 -fopub \"public key.txt\" -fopriv private_key.txt -init \"ASCII key\"\n";

    printf("EHN Group 12 Practical 3\n\n");

    if (argc < 6) {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n\n%s\n", help_message);
        return EXIT_FAILURE;
    }

    int arg;
    int e_val = 2;
    for (arg = 1; arg < argc; arg++) {
        if (!strcmp(argv[arg], "-bitLen")) // Set the number of bits to generate
        {
            args[0] = true;
            for (i = 0; i < strlen(argv[arg + 1]); i++) {
                if (!isdigit(argv[arg + 1][i])) {
                    printf("Argument \"%s\" is not a valid number\n", argv[arg + 1]);
                    return EXIT_FAILURE;
                }
            }
            num_bits = (int) strtol(argv[arg + 1], NULL, 10);
            if (num_bits < 128) {
                e_val = 0;  // Change to 0 if the key is too small.
                printf("%i is too small\nChanging e val to 3\n", num_bits);
            } else if (num_bits > 4096) {
                printf("%i is too large\nterminating...\n", num_bits);
                return EXIT_FAILURE;
            }

            printf("%i bits will be generated\n", num_bits);
            arg++; // Skip over the value parameter that follows this parameter
        } else if (!strcmp(argv[arg], "-fopub")) // Set the name of the output file
        {
            args[1] = true;
            public_key_file_name = argv[arg + 1];
            printf("Using \"%s\" as the public key file\n", public_key_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        } else if (!strcmp(argv[arg], "-fopriv")) // Set the name of the output file
        {
            args[2] = true;
            private_key_file_name = argv[arg + 1];
            printf("Using \"%s\" as the private key file\n", private_key_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        } else if (!strcmp(argv[arg], "-init")) // Set RC4 init seed
        {
            args[3] = true;
            char *rc4_seed = argv[arg + 1];
            seedlen = (int) strlen(rc4_seed);

            for (i = 0; i < 17; i++) // Clear the seed to pad with zeroes if needed
                seed[i] = 0;

            for (i = 0; i < seedlen && i < 16; i++)
                seed[i] = rc4_seed[i];

            printf("Using \"%s\" as the RC4 RNG seed.\n", seed);
            arg++; // Skip over the value parameter that follows this parameter
        } else
            printf("Invalid parameter supplied: \"%s\"\n", argv[arg]);
    }

    if (!args[0] || !args[1] || !args[2]) {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n\n%s\n", help_message);
        return EXIT_FAILURE;
    }

    if (!args[3]) {
        seed[0] = 0x01;
        seed[1] = 0x23;
        seed[2] = 0x45;
        seed[3] = 0x67;
        seed[4] = 0x89;
        seed[5] = 0xAB;
        seed[6] = 0xCD;
        seed[7] = 0xEF;
        for (i = 8; i < 17; i++)
            seed[i] = 0;
        seedlen = 8;

        printf("No RC4 RNG seed was specified, using the default value of 0123456789ABCDEF (HEX)\n");
    }

    struct rsactx_t rsactx;
    rsa_init(&rsactx);
    rc4_init(&rc4ctx, seed, seedlen);

    getkeys(&rsactx, num_bits, e_val);

    // Open the public key file to be written
    FILE *pubkeyfile;
    pubkeyfile = fopen(public_key_file_name, "w");
    U8 temp = '\n';
    if (pubkeyfile == NULL) // Output file could not be created
    {
        printf("The public key file could not be created, please make sure the program has write privileges\n");
        return EXIT_FAILURE;
    } else {
        mpz_out_str(pubkeyfile, 10, rsactx.n);
        fwrite(&temp, 1, 1, pubkeyfile);
        mpz_out_str(pubkeyfile, 10, rsactx.e);
        fwrite(&temp, 1, 1, pubkeyfile);
        fclose(pubkeyfile);
    }

    // Open the private key file to be written
    FILE *privkeyfile;
    privkeyfile = fopen(private_key_file_name, "w");
    if (privkeyfile == NULL) // Output file could not be created
    {
        printf("The private key file could not be created, please make sure the program has write privileges\n");
        return EXIT_FAILURE;
    } else {
        mpz_out_str(privkeyfile, 10, rsactx.n);
        fwrite(&temp, 1, 1, privkeyfile);
        mpz_out_str(privkeyfile, 10, rsactx.d);
        fwrite(&temp, 1, 1, privkeyfile);
        fclose(privkeyfile);
    }

    rsa_clean(&rsactx);
    printf("\nDone\n");
    return EXIT_SUCCESS;
}


// Gets the next prime from a randomly generated value from RC4 RNG
void getprime(mpz_t p, int num_bits) {
    // TODO: unsigned long is net 64 bits, gaan overflow vir meer as 128 bits
    unsigned int result;
    mpz_t temp_result;
    mpz_init_set_ui(temp_result, 1);
    mpz_t val_2;
    mpz_init_set_ui(val_2, 2);
    mpz_t val_1;
    mpz_init_set_ui(val_1, 1);

    // Loop until right length
    for (int i = 0; i < num_bits - 1; i++) {
        mpz_mul(temp_result, temp_result, val_2);
        result = (rc4_getbyte(&rc4ctx) & 0b00000001);
        if (result == 1) {
            mpz_add(temp_result, temp_result, val_1);
        }
    }
    mpz_nextprime(p, temp_result);
}


// Create the RSA key pair
void getkeys(struct rsactx_t *rsactx, int key_len, int e_selection) {
    mpz_t phi;
    mpz_t p_1, q_1, val_1;
    mpz_t phi_1;
    mpz_t remain;
    unsigned long i_1 = 1;
    int p_q_bit_len = (key_len) / 2;
    unsigned long e[3] = {3, 17, 65537};

    do {
        do {
            getprime(rsactx->p, p_q_bit_len);
            getprime(rsactx->q, p_q_bit_len); // Random prime p and q
        } while (mpz_get_ui(rsactx->p) == mpz_get_ui(rsactx->q)); // p != q

        mpz_mul(rsactx->n, rsactx->p, rsactx->q); // Set n
        mpz_set_ui(rsactx->e, e[e_selection]); //set e from common e values
        mpz_init_set_ui(val_1, i_1); // Create a mpz struct with val 1 for subtraction.

        mpz_init(p_1);
        mpz_sub(p_1, rsactx->p, val_1); // (p-1)

        mpz_init(q_1);
        mpz_sub(q_1, rsactx->q, val_1); // (q-1)

        mpz_init(phi);
        mpz_mul(phi, p_1, q_1); // phi = (p-1)(q-1)

        mpz_init(phi_1);
        mpz_add(phi_1, phi, val_1);

        mpz_init(remain);
        mpz_t count;
        mpz_init_set_ui(count, 1);
        do {
            mpz_tdiv_qr(rsactx->d, remain, phi_1, rsactx->e);
            mpz_add(count, count, val_1);
            mpz_mul(phi_1, phi, count);
            mpz_add(phi_1, phi_1, val_1);
        } while ((mpz_get_ui(remain) != 0) && (mpz_cmp(rsactx->d, phi) < 0));

    } while ((mpz_get_ui(remain) != 0) || (mpz_cmp(rsactx->d, phi) >= 0));
}
