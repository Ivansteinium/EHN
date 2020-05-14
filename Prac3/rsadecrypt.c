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



    char *private_file_name = NULL;
    char *output_file_name = NULL;
    char *input_file_name = NULL;
    unsigned char key[16+1];
    int keylen;
    char *key_file_name = NULL;
    bool args[3] = {false, false, false};

    char help_message[] = "rsaencrypt -key key -fo outputfile -KU public_key_file";
    // from guide, refine/change if necessary

    if (argc < 6)
    {
        printf("Too few arguments were supplied\n");
        printf("Proper use of the program is as follows:\n \n %s \n", help_message);
        return EXIT_FAILURE;
    }
    int arg;
    for (arg = 1; arg < argc; arg++)
    {
        if (strstr(argv[arg], "-fi") != NULL) // Set the name of the input file
        {
            args[0] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            input_file_name = argv[arg + 1];
            printf("Using %s as the key file\n", input_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (strstr(argv[arg], "-KR") != NULL) // Set the name of the private key file
        {
            args[1] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            private_file_name = argv[arg + 1];
            printf("Using %s as the input file\n", private_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (strstr(argv[arg], "-fo") != NULL) // Set the name of the output file
        {
            args[2] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            output_file_name = argv[arg + 1];
            printf("Using %s as the output file\n", output_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else
        {
            printf("Invalid parameter supplied: %s\n", argv[arg]);
            printf("Proper use of the program is as follows:\n %s \n", help_message);
            return EXIT_FAILURE;
        }
    }
}

void decrypt_rsa(mpz_t plain, mpz_t d, mpz_t n, mpz_t cipher){
    mpz_powm (plain, cipher, d, n);
}