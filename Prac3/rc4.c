#include "rc4.h"

//void swap(int *a, int *b)
//{
//    int temp;
//    temp = *a;
//    *a = *b;
//    *b = temp;
//}
//
//// Body
//void rc4_init(struct rc4info_t *rc4i, unsigned char *key, int keylen) // Set up the RC4 cipher as done in "Network
//// Security Essentials", William stallings, page 48
//{
//    int i;
//    int T[255];
//    for (i = 0; i < 256; i++) // initialise values
//    {
//        rc4i->S[i] = i;
//        T[i] = key[i % keylen];
//    }
//    int j = 0;
//    for (i = 0; i < 256; i++) // do the initial permutation of S
//    {
//        j = (j + rc4i->S[i] + T[i]) % 256;
//        swap(&(rc4i->S[i]), &(rc4i->S[j]));
//    }
//    rc4i->i = 0;
//    rc4i->j = 0;
//}
//
//unsigned char rc4_getbyte(struct rc4info_t *rc4i)// Generate a byte using the RC4 cipher as done in "Network
//// Security Essentials", William stallings, page 48
//{
//    // increment the swap indexes
//    rc4i->i = (rc4i->i + 1) % 256;
//    rc4i->j = (rc4i->j + rc4i->S[rc4i->i]) % 256;
//    // swap the values in the S array
//    swap(&(rc4i->S[rc4i->i]), &(rc4i->S[rc4i->j]));
//    // sum the swapped values
//    int t = (rc4i->S[rc4i->i] + rc4i->S[rc4i->j]) % 256;
//    return rc4i->S[t];
//}

int main(int argc, char *argv[])
{
    char *input_file_name = NULL;
    char *output_file_name = NULL;
    unsigned char key[RC4_MAX_KEY_LEN + 1];
    int keylen;
    char *key_file_name = NULL;
    bool args[3] = {false, false, false};

    char help_message[] = "rc4 -fi inputfile -fo outputfile -kf keyfile";
    // from guide, refine/change if necessary

    if (argc < 4)
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
            printf("Using %s as the input file", input_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        if (strstr(argv[arg], "-fo") != NULL) // Set the name of the output file
        {
            args[1] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            output_file_name = argv[arg + 1];
            printf("Using %s as the output file", output_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        if (strstr(argv[arg], "-kf") != NULL) // Set the name of the file containing the key
        {
            args[2] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            key_file_name = argv[arg + 1];
            printf("Using %s as the key file", key_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else
        {
            printf("Invalid parameter supplied: %s\n", argv[arg]);
            printf("Proper use of the program is as follows:\n %s \n", help_message);
            return EXIT_FAILURE;
        }
    }

    if (!args[0] || !args[1])
    {
        printf("Too few arguments were supplied\n");
        printf("Proper use of the program is as follows:\n \n %s \n", help_message);
        return EXIT_FAILURE;
    }

    int i;
    char buffer[RC4_MAX_KEY_LEN + 1];
    for (i = 0; i < RC4_MAX_KEY_LEN + 2; i++)
        buffer[i] = '\0';
    if (!args[2])
    {
        printf("Please enter the key that should be used to encrypt/decrypt the input file:");
        fgets(buffer, RC4_MAX_KEY_LEN, stdin);
        printf("\n%s will be used as the key.\n", key);
        keylen = (int) strlen(buffer) / 2;
        for (i = 0; i < keylen; i++)
        {
            key[i] = strtol((char *) (buffer[2 * i] + buffer[2 * i + 1]), NULL, 16);
        }  //TODO possibly fix this
    }
    else
    {
        FILE *keyfile;
        keyfile = fopen(key_file_name, "r");
        if (keyfile == NULL)
        {
            printf("The key file could not be opened, please check that the name of the file is correct\n");
            return EXIT_FAILURE;
        }
        else
        {
            fscanf(keyfile, "%d", &keylen);
            if (keylen < 1 || keylen > RC4_MAX_KEY_LEN)
            {
                printf("The input key file did not contain a valid key length");
                return EXIT_FAILURE;
            }
            char format[4];
            sprintf(format, "%%%ds", keylen);
            fscanf(keyfile, format, buffer); // only read keylen number of characters
            for (i = 0; i < keylen; i++)
            {
                key[i] = strtol((char *) (buffer[2 * i] + buffer[2 * i + 1]), NULL, 16);
            }
            printf("%s will be used as the key.\n", key);
        }
    }

    FILE *infile;
    infile = fopen(input_file_name, "r");
    if (infile == NULL)
    {
        printf("The input file could not be opened, please check that the name of the file is correct\n");
        return EXIT_FAILURE;
    }


}
