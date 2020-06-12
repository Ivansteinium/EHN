#include "rc4.h"


/// The main function for the RC4 encryption/decryption utility. Uses the RC4 functions in prac3.h to encrypt/decrypt
/// an input file using a key file, or using a key entered into the terminal.
int main(int argc, char *argv[])
{
    int i;
    char *input_file_name = NULL;
    char *output_file_name = NULL;
    U8 key[RC4_MAX_KEY_LEN + 2];
    int keylen;
    char *key_file_name = NULL;
    //               fi     fo     key
    bool args[3] = {false, false, false};
    char help_message[] = "\t./rc4 -arg1 value1 -arg2 value2...\n"
                          "\t\n"
                          "\tThe following arguments should then be given in this order:\n\n"
                          "\t-fi <input file>\n"
                          "\t-fo <output file>\n"
                          "\t-key <key file> (optional)\n\n"
                          "\t\nThe use of the -e or -d arguments is optional and has no effect on the operation performed"
                          "\t\nRemember to add \"double quotes\" if spaces are present in an argument\n"
                          "\t\nExample usage:\n"
                          "\t1.\t./rc4 -fi \"plain text.txt\" -fo encrypted.enc -key key.txt\n"
                          "\t2.\t./rc4 -fi encrypted.enc -fo decrypted.txt\n";

    printf("EHN Group 12 Practical 3\n\n");

    if (argc < 4)
    {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n\n%s\n", help_message);
        return EXIT_FAILURE;
    }

    int arg;
    for (arg = 1; arg < argc; arg++)
    {
        if (!strcmp(argv[arg], "-fi")) // Set the name of the input file
        {
            args[0] = true;
            input_file_name = argv[arg + 1];
            printf("Using \"%s\" as the input file\n", input_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (!strcmp(argv[arg], "-fo")) // Set the name of the output file
        {
            args[1] = true;
            output_file_name = argv[arg + 1];
            printf("Using \"%s\" as the output file\n", output_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (!strcmp(argv[arg], "-key")) // Set the name of the file containing the key
        {
            args[2] = true;
            key_file_name = argv[arg + 1];
            printf("Using \"%s\" as the key file\n", key_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if ((!strcmp(argv[arg], "-e")) || (!strcmp(argv[arg], "-d")))
            continue; // Encryption and decryption follow exact same process
        else
            printf("Invalid parameter supplied: \"%s\"\n", argv[arg]);
    }

    if (!args[0] || !args[1]) // -fi and -fo have to be specified
    {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n\n%s\n", help_message);
        return EXIT_FAILURE;
    }

    // Create variables to read the key
    char buffer[RC4_MAX_KEY_LEN + 1];

    for (i = 0; i < RC4_MAX_KEY_LEN + 1; i++)
        buffer[i] = '\0';

    if (!args[2]) // Key file is not specified, read the key from the terminal
    {
        printf("Please enter the key that should be used to encrypt/decrypt the input file (ASCII):  ");
        fgets(buffer, RC4_MAX_KEY_LEN + 1, stdin); // Read only up to the max number of characters
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
            fgets(buffer, RC4_MAX_KEY_LEN + 1, keyfile); // Read only up to the max number of characters
        }
    }

    // If a password is entered in the terminal, a newline is appended, so remove it if present
    char *newlinepos;
    newlinepos = strstr(buffer, "\n");
    if (newlinepos != NULL)
        *newlinepos = '\0';

    keylen = (int) strlen(buffer);
    for (i = 0; i < RC4_MAX_KEY_LEN + 2; i++) // Fill to pad with zeroes if needed
        key[i] = '\0';
    for (i = 0; i < keylen && i < (RC4_MAX_KEY_LEN + 1); i++) // Copy up to RC4_MAX_KEY_LEN characters
        key[i] = buffer[i];

    printf("Using \"%s\" as the key.\n", key);

    // Open the files to be read and written
    FILE *infile;
    infile = fopen(input_file_name, "r");
    FILE *outfile;
    outfile = fopen(output_file_name, "w");
    struct rc4ctx_t rc4ctx;

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
        rc4_init(&rc4ctx, key, keylen); // Initialise the RC4 structure

        U8 character;
        struct timeb start_time, end_time;
        ftime(&start_time); // Get time before operation starts

        while (fread(&character, 1, 1, infile) > 0) // Read a byte and check if input file finished reading
        {
            character ^= rc4_getbyte(&rc4ctx); // XOR read byte to encrypt
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
