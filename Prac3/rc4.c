#include "rc4.h"


/**
 * The main function for the RC4 encryption/decryption utility. Uses the RC4 functions in prac3.h to ecrypt/decrypt
 * an input file using a key file, or using a key entered into the terminal.
 * @param argc The number of arguments passed to the utility.
 * @param argv A string array of the arguments passed to the utility.
 * @return Successful execution.
 */
int main(int argc, char *argv[])
{
    int i;
    char *input_file_name = NULL;
    char *output_file_name = NULL;
    unsigned char key[RC4_MAX_KEY_LEN + 1];
    int keylen;
    char *key_file_name = NULL;
    //               fi     fo     kf
    bool args[3] = {false, false, false};
    char help_message[] = "rc4 -fi inputfile -fo outputfile -kf keyfile"; // TODO: from guide, refine/change if necessary

    if (argc < 4)
    {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n\n%s\n", help_message);
        return EXIT_FAILURE;
    }

    int arg;
    for (arg = 1; arg < argc; arg++)
    {
        if (strstr(argv[arg], "-fi") != NULL) // Set the name of the input file
        {
            args[0] = true;
            input_file_name = argv[arg + 1];
            printf("Using %s as the input file\n", input_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (strstr(argv[arg], "-fo") != NULL) // Set the name of the output file
        {
            args[1] = true;
            output_file_name = argv[arg + 1];
            printf("Using %s as the output file\n", output_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (strstr(argv[arg], "-kf") != NULL) // Set the name of the file containing the key
        {
            args[2] = true;
            key_file_name = argv[arg + 1];
            printf("Using %s as the key file\n", key_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if ((strstr(argv[arg], "-e") != NULL) || (strstr(argv[arg], "-d") != NULL))
            continue; // Encryption and decryption follow exact same process
        else
            printf("Invalid parameter supplied: %s\n", argv[arg]);
    }

    if (!args[0] || !args[1]) // -fi and -fo have to be specified
    {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n\n%s\n", help_message);
        return EXIT_FAILURE;
    }

    // Create variables to read the key
    char buffer[RC4_MAX_KEY_LEN + 2];
    char current_number[2];
    char *hex_string;

    for (i = 0; i < RC4_MAX_KEY_LEN + 3; i++)
        buffer[i] = '\0';

    if (!args[2]) // Key file is not specified, read the key from the terminal
    {
        printf("Please enter the key that should be used to encrypt/decrypt the input file:");
        fgets(buffer, RC4_MAX_KEY_LEN * 2 + 1, stdin); // Read only up to the max number of characters = 2 * max key length in bytes
        printf("\n%s will be used as the key.\n", buffer);
        keylen = (int) strlen(buffer) / 2; // 2 hex chars = 1 byte

        // Convert from hex string to int array
        hex_string = buffer;
        for (i = 0; i < keylen; i++)
        {
            strncpy(current_number, hex_string, 2); // Retrieve one byte (two hex chars)
            key[i] = (unsigned char) hex_convert(current_number, 2); // Get the integer value from the byte
            hex_string += 2; // Move to the next byte
        }
    }
    else // Read the key from the key file
    {
        FILE *keyfile;
        keyfile = fopen(key_file_name, "r");
        if (keyfile == NULL) // Key file does not exist
        {
            printf("The key file could not be opened, please check that the name of the file is correct\n");
            return EXIT_FAILURE;
        }
        else
        {
            // Read from the file
            fscanf(keyfile, "%s", buffer);
            keylen = (int) strlen(buffer);
            if (keylen < 1 || keylen > RC4_MAX_KEY_LEN)
            {
                printf("The key length is invalid");
                return EXIT_FAILURE;
            }

            // Convert from hex string to int array
            hex_string = buffer;
            for (i = 0; i < keylen; i++)
            {
                strncpy(current_number, hex_string, 2); // Retrieve one byte (two hex chars)
                key[i] = (unsigned char) hex_convert(current_number, 2); // Get the integer value from the byte
                hex_string += 2; // Move to the next byte
            }
            printf("%s will be used as the key.\n", buffer);
        }
    }

    // Open the files to be read and written
    FILE *infile;
    infile = fopen(input_file_name, "r");
    FILE *outfile;
    outfile = fopen(output_file_name, "w");
    struct rc4info_t rc4Info;

    if (infile == NULL) // Input file does not exist
    {
        printf("The input file could not be opened, please check that the name of the file is correct\n");
        if (outfile != NULL)
            fclose(outfile);
        return EXIT_FAILURE;
    }
    else if (outfile == NULL) // Output file could not be created
    {
        printf("The output file could not be created, please make sure the program has write privileges\n");
        fclose(infile);
        fclose(outfile);
        return EXIT_FAILURE;
    }
    else // Read a byte, encrypt, and write to output. Repeat until entire input file is read
    {
        rc4_init(&rc4Info, key, keylen); // Initialise the RC4 structure

        unsigned char character;
        struct timeb start_time, end_time;
        ftime(&start_time); // Get time before operation starts

        while (fread(&character, 1, 1, infile) > 0) // Read a byte and check if input file finished reading
        {
            character ^= rc4_getbyte(&rc4Info); // XOR read byte to encrypt
            fwrite(&character, 1, 1, outfile); // Write encrypted byte
        }

        ftime(&end_time); // Get time after operation ends
        fclose(infile); // Close and save files
        fclose(outfile);

        // Calculate time elapsed in ms and print
        int elapsed_time = (int) (1000.0 * (end_time.time - start_time.time) + (end_time.millitm - start_time.millitm));
        printf("Operation took %u ms\n\n", elapsed_time);
        printf("Encryption/Decryption complete \n");
    }

    return EXIT_SUCCESS;
}
