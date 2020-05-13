#include <obstack.h>
#include "rsakeygen.h"


// Body
int main(int argc, char *argv[])
{
    int num_bits = -1;
    char *private_key_file_name = NULL;
    char *public_key_file_name = NULL;
    int key[16];
    bool args[4] = {false, false, false, false};

    char help_message[] = "rsakeygen -b bits -KU public_key_file -KR private_key_file -key key\n \n"
                          "The bits specify the number of bits that need to be generated for the given key. \n"
                          "The key that will be used to set the RNG (Random Number Generator) seed is specified as "
                          "hexadecimal numbers in the command-line parameters.\n"
                          "The public_key_file is the filename to which the public key should be written. \n"
                          "The private_key_file is the filename to which the private key should be written.\n";
                          // from guide, refine/change if necessary

    if (argc < 8)
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
            printf("%i bits will be generated\n");
            arg++; // Skip over the value parameter that follows this parameter
        }
        else
        {
            printf("Invalid parameter supplied: %s\n",argv[arg]);
            printf("Proper use of the program is as follows:\n %s \n",help_message);
            return EXIT_FAILURE;
        }
    }
}