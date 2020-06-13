#include "rsadecrypt.h"

/// This utility decrypts the key used in the RC4 algorithm.
int main(int argc, char *argv[]) {
    int i;
    char *private_key_file_name = NULL;
    char *output_file_name = NULL;
    char *input_file_name = NULL;
    bool args[3] = {false, false, false};
    char help_message[] = "\t./rsadecrypt -arg1 value1 -arg2 value2...\n"
                          "\t\n"
                          "\tThe following arguments should then be given in this order:\n\n"
                          "\t-fi <input file>\n"
                          "\t-fo <output file>\n"
                          "\t-fopriv <private key file>\n\n"
                          "\t\nRemember to add \"double quotes\" if spaces are present in an argument\n"
                          "\t\nExample usage:\n"
                          "\t1.\t./rsadecrypt -fi cipher.key -fo plain.txt -fopriv \"private key.txt\"\n";

    printf("EHN Group 12 Practical 3\n\n");

    if (argc < 6) {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n\n%s\n", help_message);
        return EXIT_FAILURE;
    }

    int arg;
    for (arg = 1; arg < argc; arg++) {
        if (!strcmp(argv[arg], "-fi")) // Set the name of the input file
        {
            args[0] = true;
            input_file_name = argv[arg + 1];
            printf("Using \"%s\" as the input file\n", input_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        } else if (!strcmp(argv[arg], "-fopriv")) // Set the name of the private key file
        {
            args[1] = true;
            private_key_file_name = argv[arg + 1];
            printf("Using \"%s\" as the private RSA key file\n", private_key_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        } else if (!strcmp(argv[arg], "-fo")) // Set the name of the output file
        {
            args[2] = true;
            output_file_name = argv[arg + 1];
            printf("Using \"%s\" as the output file\n", output_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        } else
            printf("Invalid parameter supplied: \"%s\"\n", argv[arg]);
    }

    if (!args[0] || !args[1] || !args[2]) {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n\n%s\n", help_message);
        return EXIT_FAILURE;
    }

    char buffer[2049];
    for (i = 0; i < 2049; i++)
        buffer[i] = '\0';

    struct rsactx_t rsactx;
    rsa_init(&rsactx);

    // Open the private key file to be written
    FILE *privkeyfile;
    privkeyfile = fopen(private_key_file_name, "r");
    if (privkeyfile == NULL) // Key file could not be found
    {
        printf("The private key file could not be opened, please check that the name of the file is correct\n");
        return EXIT_FAILURE;
    } else {
        int result = -1;
        if (fgets(buffer, 2048, privkeyfile) != NULL) // Get n from public key file
            result = mpz_set_str(rsactx.n, buffer, 10);

        if (result == -1) // Could not read or invalid
        {
            printf("Could not read n from the private key file\n");
            return EXIT_FAILURE;
        }

        result = -1;
        if (fgets(buffer, 2048, privkeyfile) != NULL) // Get d from public key file
            result = mpz_set_str(rsactx.d, buffer, 10);

        if (result == -1) // Could not read or invalid
        {
            printf("Could not read d from the private key file\n");
            return EXIT_FAILURE;
        }
        fclose(privkeyfile);
    }

    char out_text[17];
    for (i = 0; i < 17; i++)
        buffer[i] = '\0';
    mpz_t plain, cipher, temp_val, shift, val_2;
    mpz_init(plain);
    mpz_init(cipher);
    mpz_init_set_ui(val_2, 2);
    mpz_init(temp_val);
    mpz_init(shift);

    // Open the encrypted file
    FILE *infile;
    infile = fopen(input_file_name, "r");
    if (infile == NULL) // Input file could not be found
    {
        printf("The encrypted file could not be opened, please check that the name of the file is correct\n");
        return EXIT_FAILURE;
    } else // Open output file, decrypt input and write to output
    {
        FILE *outfile;
        outfile = fopen(output_file_name, "w");
        if (outfile == NULL) // Output file could not be created
        {
            printf("The output file could not be created, please make sure the program has write privileges\n");
            return EXIT_FAILURE;
        } else // Read char, decipher char, write to output, repeat
        {
            int result = -1;
            if (fgets(buffer, 2048, infile) != NULL) // Get cipher value from the input file
                result = mpz_set_str(cipher, buffer, 10);

            if (result == -1) // Could not read or invalid
            {
                printf("Could not read the ciphertext from the input file\n");
                return EXIT_FAILURE;
            }

            decrypt_rsa(plain, rsactx.d, rsactx.n, cipher); // Decipher
            for (i = 0; i < 16; i++) {
                mpz_pow_ui(shift, val_2, 8 * (15 - i));
                mpz_tdiv_q(temp_val, plain, shift);
                out_text[i] = mpz_get_ui(temp_val);
                mpz_mul(temp_val, temp_val, shift);
                mpz_sub(plain, plain, temp_val);
            }
            out_text[16] = '\0';
            fputs(out_text, outfile);

            fprintf(outfile, "\n");
            fclose(infile);
            fclose(outfile);
        }
    }

    rsa_clean(&rsactx);
    printf("\nDone\n");
    return EXIT_SUCCESS;
}


// Uses the GMP power function to decrypt a mpz_t number
void decrypt_rsa(mpz_t plain, mpz_t d, mpz_t n, mpz_t cipher) {
    mpz_powm(plain, cipher, d, n);
}
