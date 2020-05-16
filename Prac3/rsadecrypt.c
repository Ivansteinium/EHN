#include "rsadecrypt.h"


// Body

int main(int argc, char *argv[])
{

//    int keylen = 5;
//    char *key = "abcde";
//    char rightlen[16];
//    for (int i = 0; i < 16; ++i) {
//        if(i < keylen){
//            rightlen[i] = key[i];
//        } else{
//            rightlen[i] = '\0';
//        }
//    }
//
//    char encodedKey[49]; //3*len(rightlen) (3 decimal positions for each character) +1 for leading 1
//    for(int i=0; i<49; i++)
//    {
//        encodedKey[i] = '\0';
//    }
//    encodedKey[0]='1'; // to preserve leading zeroes
//    char encode_temp[4];
//    for (int i = 0; i < 17; i++)
//    {
//        sprintf(encode_temp,"%03u",(unsigned)rightlen[i]);
//        strcat(encodedKey,encode_temp);
//    }
//
//    char *encodedKey_ptr = &encodedKey[1];
//    char encoded_temp[4];
//    encoded_temp[3] = '\0';
//    char decoded_plain[17];
//    for(int i=0;i<17; i++)
//    {
//        for(int j=0;j<3;j++)
//        {
//            encoded_temp[j] = encodedKey_ptr[3*i + j];
//        }
//        decoded_plain[i] = (char)atoi(encoded_temp);
//    }
//int x = 3;




    unsigned long i_1 = 11;
    unsigned long i_2 = 23;
    unsigned long i_3 = 187;
    mpz_t plain, d, n, cipher;
    mpz_init(cipher);
    mpz_set_ui(cipher, i_1);

    mpz_init(n);
    mpz_set_ui(n, i_3);
    mpz_init(plain);




    char *private_file_name = NULL;
    char *output_file_name = NULL;
    char *input_file_name = NULL;
    unsigned char key[16+1];
    int keylen;
    char *key_file_name = NULL;
    bool args[3] = {false, false, false};

    char help_message[] = "rsadecrypt -fi inputfile -KR private_key_file -fo outputfile";
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
            printf("Using %s as the input file\n", input_file_name);
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
            printf("Using %s as the key file\n", private_file_name);
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

    char temp[256];

    // open the public key file to be written
    FILE *krfile;
    krfile = fopen(private_file_name, "r");
    if (krfile == NULL) // key file could not be found
    {
        printf("The private key file could not be opened, please make sure the program has read privileges\n");
        fclose(krfile);
        return EXIT_FAILURE;
    } else {
        if( fgets (temp, 256, krfile)!=NULL ) {
            /* writing content to stdout */
            mpz_init(n);
            mpz_set_str(n, temp, 10);
        }
        if( fgets (temp, 256, krfile)!=NULL ) {
            /* writing content to stdout */
            mpz_init(d);
            mpz_set_str(d, temp, 10);
        }
        fclose(krfile);
    }

    // open the encrypted file
    FILE *infile;
    infile = fopen(input_file_name, "r");
    if (infile == NULL) // key file could not be found
    {
        printf("The encrypted file could not be opened, please make sure the program has read privileges\n");
        fclose(infile);
        return EXIT_FAILURE;
    } else { //open output file, decrypt input and write to output
        mpz_init(cipher);

        FILE *outfile;
        outfile = fopen(output_file_name, "w");
        if (outfile == NULL) // output file could not be created
        {
            printf("The output file could not be opened, please make sure the program has write privileges\n");
            fclose(outfile);
            return EXIT_FAILURE;
        } else { // read char, decipher a char, write to output, repeat

            mpz_init(plain);
            char outchar;
            while(fscanf(infile,"%s",temp)>0) // read
            {
                mpz_set_str(cipher, temp, 10);
                decrypt_rsa(plain, d, n, cipher); //decipher
                outchar = mpz_get_si(plain);
//                mpz_out_str(outfile, 16, plain); // write
                if(outchar == '\0')
                    break;
                fprintf(outfile,"%c",outchar);
            }
            fprintf(outfile,"\n");
            fclose(infile);
            fclose(outfile);
        }

    }


//    mpz_set_str(plain, key, 255);








//    char encoded_plain[49];
//    mpz_get_str(encoded_plain,10,plain);
//    mpz_out_str(stdout,10,plain);
//    printf("\n");
//    char *encoded_plain_ptr = &encoded_plain[1]; //delete first char
//
//    int i;
//    int j;
//    char encoded_temp[4];
//    encoded_temp[3] = '\0';
//    char decoded_plain[17];
//    for(i=0;i<17; i++)
//    {
//        for(j=0;j<3;j++)
//        {
//            encoded_temp[j] = encoded_plain_ptr[3*i + j];
//        }
//        decoded_plain[i] = (char)atoi(encoded_temp);
//    }

    // open the output file to be written


}

void decrypt_rsa(mpz_t plain, mpz_t d, mpz_t n, mpz_t cipher){
    mpz_powm (plain, cipher, d, n);
}