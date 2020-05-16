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
            printf("Using %s as the key\n", key);
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
            printf("Using %s as the output file\n", output_file_name);
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
            printf("Using %s as the rsa key file\n", public_file_name);
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

    int i;
    char rightlen[16];
    for (i = 0; i < 16; ++i)
    {
        if (i < keylen)
        {
            rightlen[i] = key[i];
        }
        else
        {
            rightlen[i] = '\0';
        }
    }
//    rightlen[16] = '\n';
//    char encodedKey[49]; //3*len(rightlen) (3 decimal positions for each character) +1 for leading 1
//    for(i=0; i<49; i++)
//    {
//        encodedKey[i] = '\0';
//    }
//    encodedKey[0]='1'; // to preserve leading zeroes
//    char encode_temp[4];
//    for (i = 0; i < 17; i++)
//    {
//        sprintf(encode_temp,"%03u",(unsigned)rightlen[i]);
//        strcat(encodedKey,encode_temp);
//    }


//    mpz_out_str(stdout,10,plain);
//    printf("\n");
//    mpz_out_raw(stdout,plain);
//    printf("\n");
//    gmp_vsscanf(rightlen, "%Zd\n" , plain);

    char temp[256];
    for (i = 0; i < 257; i++)
    {
        temp[i] = '\0';
    }
    // open the public key file to be read
    FILE *kufile;
    kufile = fopen(public_file_name, "r");
    if (kufile == NULL) // key file could not be found
    {
        printf("The public key file could not be opened, please make sure the program has read privileges\n");
        fclose(kufile);
        return EXIT_FAILURE;
    }
    else
    {
        if (fgets(temp, 256, kufile) != NULL)
        {
            mpz_init_set_str(n, temp, 10);
        }
        if (fgets(temp, 256, kufile) != NULL)
        {
            mpz_init_set_str(e, temp, 10);
        }
        fclose(kufile);
    }
//    mpz_t  plain_test;
//    mpz_init_set_str(plain_test, "10010110100101101001011010010110100101101001011010010110100101101001011010010110100101101001011010010110100101101001011010010110", 2);



//    mpz_t d;
//    mpz_init_set_str(d, "3796438167039216065323312031409113", 10);
//    mpz_powm (plain, cipher, d, n);
//    mpz_out_str(stdout, 2, plain);
//    printf("\n");

    unsigned char new = '\n';

    // open the public key file to be written
    FILE *outfile;
    outfile = fopen(output_file_name, "w");
    if (outfile == NULL) // output file could not be created
    {
        printf("The output file could not be opened, please make sure the program has write privileges\n");
        fclose(outfile);
        return EXIT_FAILURE;
    }
    else
    {
        mpz_init(cipher);
        mpz_init(plain);

        for(i=0; i< 16; i++)
        {
            mpz_set_si(plain, (int)rightlen[i]);
            encrypt_rsa(plain, e, n, cipher);
            mpz_out_str(outfile, 10, cipher);
            fprintf(outfile," ");
        }
        fwrite(&new, 1, 1, outfile);
        fclose(outfile);
    }

}

void encrypt_rsa(mpz_t plain, mpz_t e, mpz_t n, mpz_t cipher)
{
    mpz_powm(cipher, plain, e, n);
}