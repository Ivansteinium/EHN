#include "rsaencrypt.h"


// Body

int main(int argc, char *argv[])
{
    mpz_t plain, e, n, cipher;

    char *public_file_name = NULL;
    char *output_file_name = NULL;
    char *key;
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
        if (strstr(argv[arg], "-key") != NULL) // Set the name of the file containing the key
        {
            args[0] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }
            keylen = (int) strlen(argv[arg + 1]);
            key = argv[arg + 1];
            printf("Using %s as the key file\n", key);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (strstr(argv[arg], "-fo") != NULL) // Set the name of the output file
        {
            args[1] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            output_file_name = argv[arg + 1];
            printf("Using %s as the input file\n", output_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (strstr(argv[arg], "-KU") != NULL) // Set the name of the public key file
        {
            args[2] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            public_file_name = argv[arg + 1];
            printf("Using %s as the output file\n", public_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else
        {
            printf("Invalid parameter supplied: %s\n", argv[arg]);
            printf("Proper use of the program is as follows:\n %s \n", help_message);
            return EXIT_FAILURE;
        }
    }

//    unsigned long input_key = 0;
//    for (int i = 0; i < 16; ++i) {
//        input_key = input_key<<8;
//        if(i < keylen){
//            input_key = input_key | key[i];
//        }
//    }
//
//
//    char hex[34];
//    unsigned char hex_temp;
//    hex[0] = '0';
//    hex[1] = 'x';
//    for (int i = 0; i < 16; ++i) {
//        if(i < keylen){
//            hex_temp = key[i];
//            hex[i*2+2] = hex_temp>>4;
//            hex[i*2+1+2] = key[i] & 0b00001111;
//        } else {
//            hex[i*2+2] = '\0';
//            hex[i*2+1+2] = '\0';
//        }
//    }

    char rightlen[16];
    for (int i = 0; i < 16; ++i) {
        if(i < keylen){
            rightlen[i] = key[i];
        } else{
            rightlen[i] = '\0';
        }
    }
//    rightlen[16] = '\n';

    mpz_init(plain);
//    mpz_set_ui(plain, input_key); // Sets the key plaintext?
//    mpz_set_str(plain, hex, 0);
    gmp_scanf("%hh", rightlen, plain);

    char temp[256];

    // open the public key file to be written
    FILE *kufile;
    kufile = fopen(public_file_name, "r");
    if (kufile == NULL) // key file could not be found
    {
        printf("The public key file could not be opened, please make sure the program has read privileges\n");
        fclose(kufile);
        return EXIT_FAILURE;
    } else {
        if( fgets (temp, 256, kufile)!=NULL ) {
            /* writing content to stdout */
            mpz_init(n);
            mpz_set_str(n, temp, 10);
        }
        if( fgets (temp, 256, kufile)!=NULL ) {
            /* writing content to stdout */
            mpz_init(e);
            mpz_set_str(e, temp, 10);
        }
        fclose(kufile);
    }

    mpz_init(cipher);
    encrypt_rsa(plain, e, n, cipher);

    unsigned char new = '\n';

    // open the public key file to be written
    FILE *outfile;
    outfile = fopen(output_file_name, "w");
    if (outfile == NULL) // output file could not be created
    {
        printf("The output file could not be opened, please make sure the program has write privileges\n");
        fclose(outfile);
        return EXIT_FAILURE;
    } else {
        mpz_out_str(outfile, 10, cipher);
        fwrite(&new, 1, 1, outfile);
        fclose(outfile);
    }

}

void encrypt_rsa(mpz_t plain, mpz_t e, mpz_t n, mpz_t cipher){
    mpz_powm (cipher, plain, e, n);
}