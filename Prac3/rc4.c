#include "rc4.h"

/// The main function for the RC4 encryption/decryption utility. Uses the RC4 functions in prac3.h to ecrypt/decrypt
/// an input file using a key file, or using a key entered into the terminal.
/// \param argc The number of arguments passed to the utility
/// \param argv A string array of the arguments passed to the utility
/// \return Successful execution
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
            printf("Using %s as the input file\n", input_file_name);
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
        else if (strstr(argv[arg], "-kf") != NULL) // Set the name of the file containing the key
        {
            args[2] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            key_file_name = argv[arg + 1];
            printf("Using %s as the key file\n", key_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if ((strstr(argv[arg], "-e") != NULL) || (strstr(argv[arg], "-d") != NULL)) // encryption and decryption
            // follow exact same process
        {
            continue;
        }
        else
        {
            printf("Invalid parameter supplied: %s\n", argv[arg]);
            printf("Proper use of the program is as follows:\n %s \n", help_message);
            return EXIT_FAILURE;
        }
    }

    if (!args[0] || !args[1]) // -fi and -fo have to be specified
    {
        printf("Too few arguments were supplied\n");
        printf("Proper use of the program is as follows:\n \n %s \n", help_message);
        return EXIT_FAILURE;
    }

    //create variables to read the key
    int i;
    char buffer[RC4_MAX_KEY_LEN + 2];
    char currentVal[3];
    currentVal[2] = '\0';
    for (i = 0; i < RC4_MAX_KEY_LEN + 3; i++)
        buffer[i] = '\0';

    if (!args[2]) // read the key from the terminal if a key file is not specified
    {
        printf("Please enter the key that should be used to encrypt/decrypt the input file:");
        fgets(buffer, RC4_MAX_KEY_LEN*2 + 1, stdin); // read only up to the max number of characters = 2*max key
        // length in bytes
        printf("\n%s will be used as the key.\n", buffer);
        keylen = (int) strlen(buffer) / 2;
        for (i = 0; i < keylen; i++) // convert the string key to separate key bytes
        {
            currentVal[0] = buffer[2 * i];
            currentVal[1] = buffer[2 * i + 1];
            key[i] = strtol(currentVal, NULL, 16);
        }
    }
    else // read the key from the key file
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
            fscanf(keyfile, "%d", &keylen); // read the key length from the first line in the file
            if (keylen < 1 || keylen > RC4_MAX_KEY_LEN)
            {
                printf("The input key file did not contain a valid key length");
                return EXIT_FAILURE;
            }
            char format[4];
            sprintf(format, "%%%ds", keylen * 2);
            fscanf(keyfile, format, buffer); // only read keylen*2 number of characters (equal to keylen bytes)
            for (i = 0; i < keylen; i++) // convert the key string into separate hex bytes
            {
                currentVal[0] = buffer[2 * i];
                currentVal[1] = buffer[2 * i + 1];
                key[i] = strtol(currentVal, NULL, 16);
            }
            printf("%s will be used as the key.\n", buffer);
        }
    }

    // open the files to be read and written
    FILE *infile;
    infile = fopen(input_file_name, "r");
    FILE *outfile;
    outfile = fopen(output_file_name, "w");
    struct rc4info_t rc4Info;
    if (infile == NULL) // input file does not exist
    {
        printf("The input file could not be opened, please check that the name of the file is correct\n");
        fclose(infile);
        fclose(outfile);
        return EXIT_FAILURE;
    }
    else if (outfile == NULL) // output file could not be created
    {
        printf("The output file could not be opened, please make sure the program has write privileges\n");
        fclose(infile);
        fclose(outfile);
        return EXIT_FAILURE;
    }
    else // read a byte, encrypt, and write to output. Repeat until entire input file is read
    {
        rc4_init(&rc4Info, key, keylen); // initialise the RC4 structure
        unsigned char temp;
        while (fread(&temp, 1, 1, infile) > 0)// read a byte and check if input file finished reading
        {
            temp = temp ^ rc4_getbyte(&rc4Info); // xor read byte to encrypt
            fwrite(&temp, 1, 1, outfile); // write encrypted byte
        }
        fclose(infile); //close and save files
        fclose(outfile);
    }

    printf("Encryption/Decryption complete \n");
    return EXIT_SUCCESS;
}
