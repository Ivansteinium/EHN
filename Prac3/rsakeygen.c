#include "rsakeygen.h"


// TODO: remove comments
/// This utility generates a public/private key pair to be used to encrypt and decrypt the RC4 key.
int main(int argc, char *argv[])
{
//    struct rsactx_t rsa;
//    setseed(&rsa, 1);
//    rc4_init(&RC4_RNG, rsa.seed, 8);
//    mpz_t large_prime;
//    mpz_init(large_prime);
//    getprime(&rsa, large_prime, 15);

    int i;
    int num_bits = -1;
    char *private_key_file_name = NULL;
    char *public_key_file_name = NULL;
    //             binLen  fopub fopriv  init
    bool args[4] = {false, false, false, false};
    char *key = NULL;
    char help_message[] = "\t./rsakeygen -arg1 value1 -arg2 value2...\n"
                          "\t\n"
                          "\tThe following arguments should then be given in this order:\n\n"
                          "\t-bitLen <number of bits>\n"
                          "\t-fopub <public key file>\n"
                          "\t-fopriv <private key file>\n"
                          "\t-init <RC4 RNG string in ASCII>"
                          "\t\nRemember to add \"double quotes\" if spaces are present in an argument\n"
                          "\t\nExample usage:\n"
                          "\t1.\t./rsakeygen -bitLen 128 -fopub \"public key.txt\" -fopriv private_key.txt -init \"ASCII key\"\n";

    if (argc < 6)
    {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n\n%s\n", help_message);
        return EXIT_FAILURE;
    }

    int arg;
    for (arg = 1; arg < argc; arg++)
    {
        if (!strcmp(argv[arg], "-bitLen")) // Set the number of bits to generate
        {
            args[0] = true;
            for (i = 0; i < strlen(argv[arg + 1]); i++)
            {
                if (!isdigit(argv[arg + 1][i]))
                {
                    printf("Argument %s is not a valid number\n", argv[arg + 1]);
                    return EXIT_FAILURE;
                }
            }
            num_bits = (int) strtol(argv[arg + 1], NULL, 10);
            printf("%i bits will be generated\n", num_bits);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (!strcmp(argv[arg], "-fopub")) // Set the name of the output file
        {
            args[1] = true;
            public_key_file_name = argv[arg + 1];
            printf("Using %s as the public key file\n", public_key_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (!strcmp(argv[arg], "-fopriv")) // Set the name of the output file
        {
            args[2] = true;
            private_key_file_name = argv[arg + 1];
            printf("Using %s as the private key file\n", private_key_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (!strcmp(argv[arg], "-init")) // Set the key
        {
            args[3] = true;
            key = argv[arg + 1];
            printf("%s will be used as the RC4 RNG string.\n", key);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else
            printf("Invalid parameter supplied: %s\n", argv[arg]);
    }

    if (!args[0] || !args[1] || !args[2])
    {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n\n%s\n", help_message);
        return EXIT_FAILURE;
    }

    // Set the RSA key
    struct rsactx_t rsactx;
    rsa_init(&rsactx);
    int e_val = 2;  // TODO: Maybe change to 1/0 if the key is too small.
    setseed(&rsactx, 1); // TODO: change hard coding? -8 marks
    if (args[3]) // Key supplied
        rc4_init(&RC4_RNG, (U8 *) key, 8);
    else // No key supplied
        rc4_init(&RC4_RNG, rsactx.seed, 8);
    getkeys(&rsactx, num_bits, e_val);

    // Open the public key file to be written
    FILE *pubkeyfile;
    pubkeyfile = fopen(public_key_file_name, "w");
    U8 temp = '\n';
    if (pubkeyfile == NULL) // Output file could not be created
    {
        printf("The public key file could not be created, please make sure the program has write privileges\n");
        return EXIT_FAILURE;
    }
    else
    {
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
    }
    else
    {
        mpz_out_str(privkeyfile, 10, rsactx.n);
//        gmp_printf("n= %Zd\n", rsa.n);
        fwrite(&temp, 1, 1, privkeyfile);
        mpz_out_str(privkeyfile, 10, rsactx.d);
        fwrite(&temp, 1, 1, privkeyfile);
        fclose(privkeyfile);
    }
    
    rsa_clean(&rsactx);
    return EXIT_SUCCESS;

//    FILE *abc;
//    abc = fopen("abc.txt", "w");
//    mpz_out_raw(abc, rsa.n);
//    fclose(abc);
}


// Sets the RNG seed parameter of RSA struct
void setseed(struct rsactx_t *rsactx, bool default_key)
{
    if (default_key)
    {
        rsactx->seed[0] = 0x01;
        rsactx->seed[1] = 0x23;
        rsactx->seed[2] = 0x45;
        rsactx->seed[3] = 0x67;
        rsactx->seed[4] = 0x89;
        rsactx->seed[5] = 0xAB;
        rsactx->seed[6] = 0xCD;
        rsactx->seed[7] = 0xEF;
    }
    else
    {
        // TODO: find random value
    }
}


// Gets the next prime from a randomly generated value from RC4 RNG
void getprime(struct rsactx_t *rsactx, mpz_t p, int num_bits)
{
    unsigned long result = 1;
    mpz_t not_prime;
//    int num_rand_bytes = num_bits / 10;
//    unsigned int temp;
//    int remain = num_bits % 10;

    // Loop until right length
    for (int i = 0; i < num_bits - 1; i++)
    {
        result = result << 1;
        result = result | (rc4_getbyte(&RC4_RNG) & 0b00000001);
    }

//    for (int i = 0; i < num_rand_bytes; ++i)
//    {
//        result = result | 1;
//        result = result << 8;
//        result = result | rc4_getbyte(&RC4_RNG);
//        result = result << 1;
//        result = result | 1;
//    }
//
//    if (remain > 0)
//    {
//        temp = rc4_getbyte(&RC4_RNG) >> (8 - remain);
//        result = result << remain;
//        result = result | temp;
//    }

    mpz_init_set_ui(not_prime, result);
    mpz_nextprime(p, not_prime);
}


// Create the RSA key pair
void getkeys(struct rsactx_t *rsactx, int key_len, int e_selection)
{
    mpz_t phi;
    mpz_t p_1, q_1, val_1;
    mpz_t phi_1;
    mpz_t remain;
    unsigned long i_1 = 1;
    int p_q_bit_len = (key_len) / 2;
    unsigned long e[3] = {3, 17, 65537};

    do
    {
        do
        {
            getprime(rsactx, rsactx->p, p_q_bit_len);
            getprime(rsactx, rsactx->q, p_q_bit_len); // Random prime p and q
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

//        mpz_init(mod_out);
//        mpz_mod(mod_out, rsactx->e, phi); // e mod phi

        mpz_init(phi_1);
        mpz_add(phi_1, phi, val_1);

        mpz_init(remain);
        mpz_t count;
        mpz_init_set_ui(count, 1);
        do
        {
            mpz_tdiv_qr(rsactx->d, remain, phi_1, rsactx->e);
            mpz_add(count, count, val_1);
            mpz_mul(phi_1, phi, count);
            mpz_add(phi_1, phi_1, val_1);
        } while ((mpz_get_ui(remain) != 0) && (mpz_cmp(rsactx->d, phi) < 0));

//        mpz_tdiv_qr(rsactx->d, remain, phi_1, rsactx->e);
//        mpz_mod(remain, phi_1, rsactx->d);

    } while ((mpz_get_ui(remain) != 0) || (mpz_cmp(rsactx->d, phi) >= 0));

    mpz_out_str(stdout, 10, phi_1);
    printf("\n");
    mpz_out_str(stdout, 10, rsactx->d);
    printf("\n");
    printf("phi: %lu\n", mpz_get_ui(phi_1));
    printf("d: %lu\n", mpz_get_ui(rsactx->d));
}
