#include "rsaencrypt.h"

/// This utility encrypts the key used in the RC4 algorithm.
int main(int argc, char *argv[]) {
    int i;
    char *public_key_file_name = NULL;
    char *output_file_name = NULL;
    char key[17];
    bool args[3] = {false, false, false};
    char help_message[] = "\t./rsaencrypt -arg1 value1 -arg2 value2...\n"
                          "\t\n"
                          "\tThe following arguments should then be given in this order:\n\n"
                          "\t-key <key in ASCII>\n"
                          "\t-fo <output file>\n"
                          "\t-fopub <public key file>\n\n"
                          "\t\nRemember to add \"double quotes\" if spaces are present in an argument\n"
                          "\t\nExample usage:\n"
                          "\t1.\t./rsaencrypt -key \"ASCII key\" -fo cipher.key -fopub \"public key.txt\"\n";

    printf("EHN Group 12 Practical 3\n\n");

    if (argc < 6) {
        printf("Too few arguments were supplied\n"
               "Proper use of the program is as follows:\n\n%s\n", help_message);
        return EXIT_FAILURE;
    }

    int arg;
    for (arg = 1; arg < argc; arg++) {
        if (!strcmp(argv[arg], "-key")) // Set the name of the file containing the key
        {
            args[0] = true;
            int keylen = (int) strlen(argv[arg + 1]);
            for (i = 0; i < 17; i++) // Fill to pad with zeroes if needed
                key[i] = '\0';
            for (i = 0; i < keylen && i < 16; i++) // Copy up to 16 characters
                key[i] = argv[arg + 1][i];
            printf("Using \"%s\" as the key\n", key);
            arg++; // Skip over the value parameter that follows this parameter
        } else if (!strcmp(argv[arg], "-fo")) // Set the name of the output file
        {
            args[1] = true;
            output_file_name = argv[arg + 1];
            printf("Using \"%s\" as the output file\n", output_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        } else if (!strcmp(argv[arg], "-fopub")) // Set the name of the public key file
        {
            args[2] = true;
            public_key_file_name = argv[arg + 1];
            printf("Using \"%s\" as the public RSA key file\n", public_key_file_name);
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

    // Open the public key file to be read
    FILE *pubkeyfile;
    pubkeyfile = fopen(public_key_file_name, "r");
    if (pubkeyfile == NULL) // Key file could not be found
    {
        printf("The encrypted file could not be opened, please check that the name of the file is correct\n");
        return EXIT_FAILURE;
    } else {
        int result = -1;
        if (fgets(buffer, 2048, pubkeyfile) != NULL) // Get n from public key file
            result = mpz_set_str(rsactx.n, buffer, 10);

        if (result == -1) // Could not read or invalid
        {
            printf("Could not read n from the private key file\n");
            return EXIT_FAILURE;
        }

        result = -1;
        if (fgets(buffer, 2048, pubkeyfile) != NULL) // Get e from public key file
            result = mpz_set_str(rsactx.e, buffer, 10);

        if (result == -1) // Could not read or invalid
        {
            printf("Could not read e from the private key file\n");
            return EXIT_FAILURE;
        }
        fclose(pubkeyfile);
    }

    mpz_t plain, cipher, temp_val, total, byte;
    mpz_init(cipher);
    mpz_init(plain);
    mpz_init_set_ui(total, key[0]);
    mpz_init_set_ui(byte, 256);
    mpz_init(temp_val);
    for (int j = 1; j < 16; ++j) {
        mpz_mul(total, total, byte); // Shift byte
        mpz_set_ui(temp_val, key[j]);
        mpz_add(total, total, temp_val);
    }

    // Open the public key file to be written
    FILE *outfile;
    outfile = fopen(output_file_name, "w");
    if (outfile == NULL) // Output file could not be created
    {
        printf("The output file could not be created, please make sure the program has write privileges\n");
        return EXIT_FAILURE;
    } else {

        encrypt_rsa(total, rsactx.e, rsactx.n, cipher);
        mpz_out_str(outfile, 10, cipher);

        U8 new = '\n';
        fwrite(&new, 1, 1, outfile);
        new = '\0';
        fwrite(&new, 1, 1, outfile);
    }
    rsa_clean(&rsactx);
    printf("\nDone\n");
    return EXIT_SUCCESS;
}


// Uses the GMP power function to encrypt a mpz_t number
void encrypt_rsa(mpz_t plain, mpz_t e, mpz_t n, mpz_t cipher) {
    mpz_powm(cipher, plain, e, n);
}
