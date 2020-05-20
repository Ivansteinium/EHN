#include "rsaencrypt.h"


// TODO: complete
/**
 * 
 * @param argc 
 * @param argv 
 * @return 
 */
int main(int argc, char *argv[])
{
    int i;
    mpz_t plain, e, n, cipher;
    char *key_file_name = NULL;
    char *output_file_name = NULL;
    char *key;
    int keylen;
    //               key    fo     KU
    bool args[3] = {false, false, false};

    char help_message[] = "rsaencrypt -key key -fo outputfile -KU public_key_file"; // TODO: from guide, refine/change if necessary

    if (argc < 6)
    {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n \n %s \n", help_message);
        return EXIT_FAILURE;
    }
    
    int arg;
    for (arg = 1; arg < argc; arg++)
    {
        if (strstr(argv[arg], "-key") != NULL) // Set the name of the file containing the key
        {
            args[0] = true;
            keylen = (int) strlen(argv[arg + 1]);
            key = argv[arg + 1];
            printf("Using %s as the key\n", key);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (strstr(argv[arg], "-fo") != NULL) // Set the name of the output file
        {
            args[1] = true;
            output_file_name = argv[arg + 1];
            printf("Using %s as the output file\n", output_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (strstr(argv[arg], "-KU") != NULL) // Set the name of the public key file
        {
            args[2] = true;
            key_file_name = argv[arg + 1];
            printf("Using %s as the rsa key file\n", key_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else
            printf("Invalid parameter supplied: %s\n", argv[arg]);
    }

    if (!args[0] || !args[1] || !args[2])
    {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n\n %s\n", help_message);
        return EXIT_FAILURE;
    }

//    unsigned long input_key = 0;
//    for (int i = 0; i < 16; i++)
//    {
//        input_key = input_key << 8;
//        if (i < keylen)
//            input_key = input_key | key[i];
//    }
//
//    char hex[34];
//    unsigned char hex_temp;
//    hex[0] = '0';
//    hex[1] = 'x';
//    for (int i = 0; i < 16; i++)
//    {
//        if (i < keylen)
//        {
//            hex_temp = key[i];
//            hex[i * 2 + 2] = hex_temp >> 4;
//            hex[i * 2 + 1 + 2] = key[i] & 0b00001111;
//        }
//        else
//        {
//            hex[i * 2 + 2] = '\0';
//            hex[i * 2 + 1 + 2] = '\0';
//        }
//    }

    char rightlen[16];
    for (i = 0; i < 16; i++)
    {
        if (i < keylen)
            rightlen[i] = key[i];
        else
            rightlen[i] = '\0';
    }

    mpz_t temp_val, total, byte;
    mpz_init_set_ui(total, rightlen[0]);
    mpz_init_set_ui(byte, 256);
    mpz_init(temp_val);
    for (int j = 1; j < 16; ++j)
    {
        mpz_mul(total, total, byte); // Shift byte
        mpz_set_ui(temp_val, rightlen[j]);
        mpz_add(total, total, temp_val);
    }
    mpz_out_str(stdout, 2, total);

//    rightlen[16] = '\n';
//    char encodedKey[49]; // 3 * len(rightlen) (3 decimal positions for each character) +1 for leading 1
//    for (i = 0; i < 49; i++)
//        encodedKey[i] = '\0';
//    encodedKey[0] = '1'; // To preserve trailing zeroes
//    char encode_temp[4];
//    for (i = 0; i < 17; i++)
//    {
//        sprintf(encode_temp, "%03u", (unsigned) rightlen[i]);
//        strcat(encodedKey, encode_temp);
//    }

//    mpz_out_str(stdout,10,plain);
//    printf("\n");
//    mpz_out_raw(stdout,plain);
//    printf("\n");
//    gmp_vsscanf(rightlen, "%Zd\n" , plain);

    char buffer[257];
    for (i = 0; i < 257; i++)
        buffer[i] = '\0';
    
    // Open the public key file to be read
    FILE *kufile;
    kufile = fopen(key_file_name, "r");
    if (kufile == NULL) // Key file could not be found
    {
        printf("The encrypted file could not be opened, please check that the name of the file is correct\n");
        return EXIT_FAILURE;
    }
    else
    {
        if (fgets(buffer, 256, kufile) != NULL)
            mpz_init_set_str(n, buffer, 10);
        if (fgets(buffer, 256, kufile) != NULL)
            mpz_init_set_str(e, buffer, 10);
        fclose(kufile);
    }
    
//    mpz_t plain_test;
//    mpz_init_set_str(plain_test, "10010110100101101001011010010110100101101001011010010110100101101001011010010110100101101001011010010110100101101001011010010110", 2);
//    mpz_t d;
//    mpz_init_set_str(d, "3796438167039216065323312031409113", 10);
//    mpz_powm(plain, cipher, d, n);
//    mpz_out_str(stdout, 2, plain);
//    printf("\n");

    // Open the public key file to be written
    FILE *outfile;
    outfile = fopen(output_file_name, "w");
    unsigned char new = '\n';
    if (outfile == NULL) // Output file could not be created
    {
        printf("The output file could not be created, please make sure the program has write privileges\n");
        return EXIT_FAILURE;
    }
    else
    {
        mpz_init(cipher);
        mpz_init(plain);

//        for (i = 0; i < 16; i++)
//        {
//            mpz_set_si(plain, (int) rightlen[i]);
//            encrypt_rsa(plain, e, n, cipher);
//            mpz_out_str(outfile, 10, cipher);
//            fprintf(outfile, " ");
//        }

        encrypt_rsa(total, e, n, cipher);
        mpz_out_str(outfile, 10, cipher);
        fwrite(&new, 1, 1, outfile);
        fclose(outfile);
    }
}


void encrypt_rsa(mpz_t plain, mpz_t e, mpz_t n, mpz_t cipher)
{
    mpz_powm(cipher, plain, e, n);
}
