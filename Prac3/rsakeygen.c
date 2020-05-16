#include <obstack.h>
#include "rsakeygen.h"

// Body
int main(int argc, char *argv[])
{
//    struct rsactx_t rsa;
//    setseed(&rsa, 1);
//    rc4_init(&RC4_RNG, rsa.seed, 8);
//    mpz_t large_prime;
//    mpz_init(large_prime);
    //getprime(&rsa, large_prime, 15);


    int x = 1;
    int num_bits = -1;
    char *private_key_file_name = NULL;
    char *public_key_file_name = NULL;
    int key[16];
    bool args[4] = {false, false, false, false};
    int message_len = 0;
    unsigned char *message = NULL;

    char help_message[] = "rsakeygen -b bits -KU public_key_file -KR private_key_file -key key\n \n"
                          "The bits specify the number of bits that need to be generated for the given key. \n"
                          "The key that will be used to set the RNG (Random Number Generator) seed is specified as "
                          "hexadecimal numbers in the command-line parameters.\n"
                          "The public_key_file is the filename to which the public key should be written. \n"
                          "The private_key_file is the filename to which the private key should be written.\n";
                          // from guide, refine/change if necessary

    if (argc < 6)
    {
        printf("Too few arguments were supplied\n");
        printf("Proper use of the program is as follows:\n \n %s \n",help_message);
        return EXIT_FAILURE;
    }
    int arg;
    for (arg = 1; arg < argc; arg++)
    {
        if (strstr(argv[arg], "-b") != NULL) // Set the number of bits to generate
        {
            args[0] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            int i;
            for (i = 0; i < strlen(argv[arg + 1]); i++)
            {
                if (!isdigit(argv[arg + 1][i]))
                {
                    printf("argument %s is not a valid number.\n", argv[arg + 1]);
                    return EXIT_FAILURE;
                }
            }
            num_bits = (int) strtol(argv[arg + 1], NULL, 10);
            printf("%i bits will be generated\n", num_bits);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (strstr(argv[arg], "-KU") != NULL) // Set the name of the output file
        {
            args[1] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            public_key_file_name = argv[arg + 1];
            printf("Using %s as the public key file\n", public_key_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (strstr(argv[arg], "-KR") != NULL) // Set the name of the output file
        {
            args[2] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            private_key_file_name = argv[arg + 1];
            printf("Using %s as the private key file\n", private_key_file_name);
            arg++; // Skip over the value parameter that follows this parameter
        }
        else if (strstr(argv[arg], "-key") != NULL) // Set the input message
        {
            args[3] = true;
            if (arg + 1 >= argc)
            {
                printf("Too few arguments were supplied\n");
                return EXIT_FAILURE;
            }

            // Take message as hex input
            char *parameter = argv[arg + 1];
            message_len = strlen(parameter) / 2; // 2 hex chars = 1 byte

            message = (unsigned char *) malloc((message_len + 17) * sizeof(unsigned char)); // + 17 if incomplete block to pad with zeroes

            for (int i = message_len; i < message_len + 17; i++) // Fill with zeroes to pad if needed + null terminator
                message[i] = '\0';

            // Convert from hex string to int array
            char current_number[2];
            for (int i = 0; i < message_len; i++)
            {
                strncpy(current_number, parameter, 2); // Retrieve one byte (two hex chars)
                message[i] = (unsigned char) hex_convert(current_number, 2); // Get the integer value from the byte
                parameter += 2; // Move to the next byte
            }

            printf("Seed key value (HEX): ");
            print_hex_string(message, message_len);
            printf("\n");
            arg++; // Skip over the value parameter that follows this parameter
        }

        else
        {
            printf("Invalid parameter supplied: %s\n",argv[arg]);
            printf("Proper use of the program is as follows:\n %s \n",help_message);
            return EXIT_FAILURE;
        }
    }

    // set the RSA key
    struct rsactx_t rsa;
    int e_val = 2;  // maybe change to 1/0 if the key is too small.


    /* Needs key */
    setseed(&rsa, 1);
    if (args[3]){
        rc4_init(&RC4_RNG, message, 8);
    } else{
        rc4_init(&RC4_RNG, rsa.seed, 8);
    }

    getkeys(&rsa, num_bits, e_val);

    unsigned char temp = '\n';

    // open the public key file to be written
    FILE *kufile;
    kufile = fopen(public_key_file_name, "w");
    if (kufile == NULL) // output file could not be created
    {
        printf("The public key file could not be opened, please make sure the program has write privileges\n");
        fclose(kufile);
        return EXIT_FAILURE;
    } else {
        mpz_out_str(kufile, 10, rsa.n);
        fwrite(&temp, 1, 1, kufile);
        mpz_out_str(kufile, 10, rsa.e);
        fwrite(&temp, 1, 1, kufile);
        fclose(kufile);
    }

    // open the private key file to be written
    FILE *krfile;
    krfile = fopen(private_key_file_name, "w");
    if (krfile == NULL) // output file could not be created
    {
        printf("The private key file could not be opened, please make sure the program has write privileges\n");
        fclose(krfile);
        return EXIT_FAILURE;
    } else {
        mpz_out_str(krfile, 10, rsa.n);
//        gmp_printf("n= %Zd\n", rsa.n);
        fwrite(&temp, 1, 1, krfile);
        mpz_out_str(krfile, 10, rsa.d);
        fwrite(&temp, 1, 1, krfile);
        fclose(krfile);
    }


//    FILE *abc;
//    abc = fopen("abc.txt", "w");
//    mpz_out_raw(abc, rsa.n);
//    fclose(abc);
}



void setseed(struct rsactx_t *rsa_k, int same_key){
    if (same_key){
        rsa_k->seed[0] = 0x01;
        rsa_k->seed[1] = 0x23;
        rsa_k->seed[2] = 0x45;
        rsa_k->seed[3] = 0x67;
        rsa_k->seed[4] = 0x89;
        rsa_k->seed[5] = 0xAB;
        rsa_k->seed[6] = 0xCD;
        rsa_k->seed[7] = 0xEF;
    } else {
        // find random value
    }
}

void getprime(struct rsactx_t *rsa_k, mpz_t p, int num_bits){
    unsigned long result = 1;
    mpz_t not_prime;
//    int num_rand_bytes = num_bits/10;
//    unsigned int temp;
//    int remain = num_bits%10;

    // Loop until right length
    for (int i = 0; i < num_bits-1; ++i){
        result = result << 1;
        result = result | (rc4_getbyte(&RC4_RNG) & 0b00000001);
    }

//    for (int i = 0; i < num_rand_bytes; ++i){
//        result = result | 1;
//        result = result << 8;
//        result = result | rc4_getbyte(&RC4_RNG);
//        result = result << 1;
//        result = result | 1;
//    }
//
//    if (remain>0){
//        temp = rc4_getbyte(&RC4_RNG)>>(8-remain);
//        result = result<<remain;
//        result = result | temp;
//    }

    mpz_init_set_ui (not_prime, result);
    mpz_nextprime(p, not_prime);
}

void getkeys(struct rsactx_t *rsa_k, int key_len, int e_selection){
    mpz_t phi;
    mpz_t p_1, q_1, val_1;
    mpz_t phi_1;
    mpz_t remain;
    unsigned long i_1 = 1;
    int p_q_bit_len = (key_len)*300 ;/* /2; */
    unsigned long e[3] = {3, 17, 65537};
//    mpz_init(rsa_k->p);
//    mpz_init(rsa_k->q);
//    mpz_init(rsa_k->n);
//    mpz_init(p_1);
//    mpz_init(q_1);
//    mpz_init_set_ui (rsa_k->e, e[e_selection]);
//    mpz_init_set_ui (val_1, i_1);
//    mpz_init(phi);
//    mpz_init(phi_1);
//    mpz_init(rsa_k->d);
//    mpz_init(remain);

    do {
//        mpz_clear(rsa_k->p);
//        mpz_clear(rsa_k->q);
//        mpz_clear(rsa_k->n);
//        mpz_clear(p_1);
//        mpz_clear(q_1);
//        mpz_clear(rsa_k->e);
//        mpz_clear(val_1);
//        mpz_clear(phi);
//        mpz_clear(phi_1);
//        mpz_clear(rsa_k->d);
//        mpz_clear(remain);

        do {
            mpz_init(rsa_k->p);
            getprime(rsa_k, rsa_k->p, p_q_bit_len);

            mpz_init(rsa_k->q);
            getprime(rsa_k, rsa_k->q, p_q_bit_len); // Random prime p and q
        } while (mpz_get_ui(rsa_k->p) == mpz_get_ui(rsa_k->q)); // p != q

        mpz_init(rsa_k->n);
        mpz_mul(rsa_k->n, rsa_k->p, rsa_k->q); // Set n

        mpz_init_set_ui (rsa_k->e, e[e_selection]); //set e from common e values

        mpz_init_set_ui (val_1, i_1); // Create a mpz struct with val 1 for subtraction.
        mpz_init(p_1);
        mpz_sub(p_1, rsa_k->p, val_1); // (p-1)

        mpz_init(q_1);
        mpz_sub(q_1, rsa_k->q, val_1); // (q-1)

        mpz_init(phi);
        mpz_mul(phi, p_1, q_1); // phi = (p-1)(q-1)

//    mpz_init(mod_out);
//    mpz_mod (mod_out, rsa_k->e, phi); // e mod phi

        mpz_init(phi_1);
        mpz_add (phi_1, phi, val_1);

        mpz_init(rsa_k->d);
        mpz_init(remain);
        mpz_tdiv_qr(rsa_k->d, remain, phi_1, rsa_k->e);
//        mpz_mod (remain, phi_1, rsa_k->d);
    } while ((mpz_get_ui(remain) != 0) || (mpz_cmp(rsa_k->d, phi) >= 0));

    mpz_out_str(stdout, 10, phi_1);
    printf("\n");
    mpz_out_str(stdout, 10, rsa_k->d);
    printf("\n");
    printf("phi: %lu\n", mpz_get_ui(phi_1));
    printf("d: %lu\n", mpz_get_ui(rsa_k->d));
    unsigned long temp = 14851388866727294549;
    int x = temp % 65537;
}

// Print a c-string up to a certain length in hex
void print_hex_string(unsigned char hex_string[], int message_len)
{
    int i;
    for (i = 0; i < message_len; i++)
        printf("%02X", hex_string[i]);
}

// Convert hex to int, done because the system hex converter is unreliable
int hex_convert(char hex_string[], int length)
{
    int result = 0;
    int base = 1;

    int i;
    for (i = length; i > 0; i--)
    {
        switch (hex_string[i - 1])
        {
            case '0': {break;}
            case '1': {result += base * 1; break;}
            case '2': {result += base * 2; break;}
            case '3': {result += base * 3; break;}
            case '4': {result += base * 4; break;}
            case '5': {result += base * 5; break;}
            case '6': {result += base * 6; break;}
            case '7': {result += base * 7; break;}
            case '8': {result += base * 8; break;}
            case '9': {result += base * 9; break;}
            case 'A': {result += base * 10; break;}
            case 'B': {result += base * 11; break;}
            case 'C': {result += base * 12; break;}
            case 'D': {result += base * 13; break;}
            case 'E': {result += base * 14; break;}
            case 'F': {result += base * 15; break;}
            case 'a': {result += base * 10; break;}
            case 'b': {result += base * 11; break;}
            case 'c': {result += base * 12; break;}
            case 'd': {result += base * 13; break;}
            case 'e': {result += base * 14; break;}
            case 'f': {result += base * 15; break;}
            default:
            {
                printf("The input given (\'%c\') is not a valid HEX character\nTerminating...\n", hex_string[i]);
                exit(EXIT_FAILURE);
            }
        }

        base *= 16;
    }

    return result;
}