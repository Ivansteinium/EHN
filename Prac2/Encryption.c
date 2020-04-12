#include "Encryption.h"


int main(int argc, char *argv[])
{
    int i;
    bool test = false;
    bool method; // CBC if false, CFB if true
    int operation = -1; // encrypt if false, decrypt if true
    int mode = -1; // AES128, AES192, AES256 macros
    int message_len;
    unsigned char message[MAX_REQ_LEN];
    int *user_key;
    int IV[16];

    for (i = 0; i < MAX_REQ_LEN; i++)
        message[i] = '\0';

    // Greeting
    printf("EHN 410 Group 12 Practical 2\n\n");

    if (argc < 6)
    {
        printf("All parameters are not given, performing tests...\n\n");
        test = true;
    } else
    {
        for (i = 1; i < argc; i++)
        {
            char *parameter = strstr(argv[i],"=") + 1;

            if (strstr(argv[i], "width=") != NULL) // Set AES width
            {
                if (!strcmp(parameter, "AES128"))
                {
                    mode = AES128;
                    printf("AES128 selected\n");
                } else if (!strcmp(parameter, "AES192"))
                {
                    mode = AES192;
                    printf("AES192 selected\n");
                } else if (!strcmp(parameter, "AES256"))
                {
                    mode = AES256;
                    printf("AES256 selected\n");
                } else
                {
                    printf("Parameter '%s' is not a valid parameter for 'width='\n", parameter);
                    printf("Valid parameters are 'AES128', 'AES192' and 'AES256'\n");
                    return EXIT_FAILURE;
                }
            } else if (strstr(argv[i], "chain=") != NULL) // Set chaining mode
            {
                if(!strcmp(parameter, "CBC"))
                {
                    method = false;
                    printf("Cipher Block Chaining method selected\n\n");
                } else if(!strcmp(parameter, "CFB"))
                {
                    method = true;
                    printf("Cipher Feedback method selected\n\n");
                } else
                {
                    printf("Parameter '%s' is not a valid parameter for 'chain='", parameter);
                    printf("Valid parameters are 'CBC' and 'CFB'\n");
                    return EXIT_FAILURE;
                }
            } else if (strstr(argv[i], "op=") != NULL) // Set operation (encrypt or decrypt)
            {
                if (!strcmp(parameter, "E"))
                    operation = false;
                else if (!strcmp(parameter, "D"))
                    operation = true;
                else
                {
                    printf("Parameter '%s' is not a valid parameter for 'op='", parameter);
                    printf("Valid parameters are 'E' for encrypt and 'D' for decrypt\n");
                    return EXIT_FAILURE;
                }
            } else if (strstr(argv[i], "key=") != NULL) // Set the user key
            {
                if (mode == -1)
                {
                    printf("The AES width must be specified before the key is given\n");
                    printf("Specify this with 'width='\n");
                    return EXIT_FAILURE;
                } else
                {
                    int key_size;
                    if (mode == AES128)
                        key_size = AES128_KEY_SIZE;
                    else if (mode == AES192)
                        key_size = AES192_KEY_SIZE;
                    else
                        key_size = AES256_KEY_SIZE;

                    if (strlen(parameter) == 2 * key_size) // 16 bytes for AES128, 24 bytes for AES192, 32 bytes for ARS256
                    {
                        user_key = (int *) malloc(key_size * sizeof(int));

                        // Convert from hex string to int array
                        int pos;
                        char current_number[2];
                        for (pos = 0; pos < key_size; pos++)
                        {
                            strncpy(current_number, parameter, 2); // Retrieve one byte (two hex chars)
                            user_key[pos] = (int) strtol(current_number, NULL, 16); // Get the integer value from the byte
                            parameter += 2; // Move to the next byte
                        }
                    } else
                    {
                        printf("The key size given does not match the expected length for the specified width\n");
                        printf("Input the key with 'key=' where the key is given in hexadecimal, ex. '1A2F0C32...'\n");
                        return EXIT_FAILURE;
                    }
                }
            } else if (strstr(argv[i], "msg=") != NULL) // Set the input message
            {
                if (operation == -1)
                {
                    printf("The operation must be specified before the message is given\n");
                    printf("Specify this with 'op='\n");
                    return EXIT_FAILURE;
                } else if (operation == false) // Encrypt
                {
                    // Take message as ASCII input
                    message_len = strlen(parameter);
                    if (message_len > MAX_REQ_LEN)
                    {
                        printf("The message is too long, a maximum of %d bytes may be given with 'msg='\n", MAX_REQ_LEN);
                        return EXIT_FAILURE;
                    } else
                        strcpy(message, parameter);
                } else // Deprypt
                {
                    // Take message as hex input
                    message_len = strlen(parameter) / 2;
                    if (message_len > MAX_REQ_LEN)
                    {
                        printf("The message is too long, a maximum of %d bytes may be given with 'msg='\n", MAX_REQ_LEN);
                        return EXIT_FAILURE;
                    } else
                    {
                        // Convert from hex string to int array
                        int pos;
                        char current_number[2];
                        for (pos = 0; pos < message_len; pos++)
                        {
                            strncpy(current_number, parameter, 2); // Retrieve one byte (two hex chars)
                            message[pos] = (unsigned char) strtol(current_number, NULL, 16); // Get the integer value from the byte
                            parameter += 2; // Move to the next byte
                        }
                    }
                }
            } else if (strstr(argv[i], "iv=") != NULL) // Set the initialization vector
            {
                if (strlen(parameter) == 32)
                {
                    // Convert from hex string to int array
                    int pos;
                    char current_number[2];
                    for (pos = 0; pos < 16; pos++)
                    {
                        strncpy(current_number, parameter, 2); // Retrieve one byte (two hex chars)
                        IV[pos] = (int) strtol(current_number, NULL, 16); // Get the integer value from the byte
                        parameter += 2; // Move to the next byte
                    }
                } else
                {
                    printf("The initialization vector size given is not 16 bytes\n");
                    printf("Input the initialization vector with 'iv=' where the vector is given in hexadecimal, ex. '1A2F0C32...'\n");
                    return EXIT_FAILURE;
                }
            } else
            {
                printf("Invalid parameter: %s\n", argv[i]);
                printf("Usage:\n"
                       "./Encrpytion Argument1 Argument2 ...\n"
                       "\t\n"
                       "\tThe arguments are structured as follows: 'parameter=value'\n"
                       "\tThe available settings are: 'width=', 'chain=', 'op=', 'key=', 'msg=' and 'iv='\n"
                       "\t\n"
                       "\t'width=' specifies the AES width, valid parameters are 'AES128', 'AES192' and 'AES256'\n"
                       "\t'chain=' specifies the chaining mode, valid parameters are 'CBC' and 'CFB'\n"
                       "\t'op=' specifies the operation to be performed, valid parameters are 'E' for encrypt and 'D' for decrypt\n"
                       "\t'key=' specifies the user key given in hexadecimal, ex. '1A2F0C32...'\n"
                       "\t'msg=' specifies the message to be processed, ex. 'Lorem ipsum dolor sit amet.'"
                       "\t'iv=' specifies the 16-byte initialization vector to be used\n"
                       );
                return EXIT_FAILURE;
            }
        }
    }

    if (test)
    {
        //    **** TESTING PURPOSES **** /*
        int AES128_user_key[AES128_USER_KEY_SIZE] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F,
                                                     0x6E, 0x61, 0x6C, 0x69};
        int AES192_user_key[AES192_USER_KEY_SIZE] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F,
                                                     0x6E, 0x61, 0x6C, 0x69, 0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E};
        int AES256_user_key[AES256_USER_KEY_SIZE] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F,
                                                     0x6E, 0x61, 0x6C, 0x69, 0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E,
                                                     0x63, 0x74, 0x69, 0x6F, 0x6E, 0x61, 0x6C, 0x69};
        int IV_test[16] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x61, 0x6C, 0x69};
        int AES128_expanded_key[AES128_KEY_SIZE];
        int AES192_expanded_key[AES192_KEY_SIZE];
        int AES256_expanded_key[AES256_KEY_SIZE];
        int test_word[4] = {0x3A, 0x65, 0x71, 0x1B};
        int x;
        int test_cols[4][4] = {{0x74, 0x20, 0x61, 0x73},
                               {0x68, 0x69, 0x20, 0x74},
                               {0x69, 0x73, 0x74, 0x2e},
                               {0x73, 0x20, 0x65, 0x2e}};

        printf("----Testing word rotate----\n");
        printf("Original\n");
        print_word(test_word, 4);
        AES_word_rotate(test_word, 4, 1, false);
        printf("\nOne rotation\n");
        print_word(test_word, 4);
        AES_word_rotate(test_word, 4, 1, true);
        printf("\nOne inverse rotation\n");
        print_word(test_word, 4);
        AES_word_rotate(test_word, 4, 2, false);
        printf("\nTwo rotations\n");
        print_word(test_word, 4);
        AES_word_rotate(test_word, 4, 2, true);
        printf("\nTwo inverse rotations\n");
        print_word(test_word, 4);
        AES_word_rotate(test_word, 4, 3, false);
        printf("\nThree rotations\n");
        print_word(test_word, 4);
        AES_word_rotate(test_word, 4, 3, true);
        printf("\nThree inverse rotations\n");
        print_word(test_word, 4);
        printf("\n\n");

        printf("----Testing S-transform----\n");
        printf("Original\n3A\n");
        x = AES_s_box_transform(0x3A, false);
        printf("\nS-transformed\n%02X\n", x);
        x = AES_s_box_transform(x, true);
        printf("\nInverse s-transformed\n%02X\n", x);
        printf("\n\n");

        printf("----Testing key scheduler----\n");
        printf("Original\n");
        print_word(test_word, 4);
        AES_key_scheduler(test_word, 1);
        printf("\nKey scheduled with rcon = 1\n");
        print_word(test_word, 4);
        printf("\n\n");

        // Test cols changed by key scheduler
        test_word[0] = 0x3A;
        test_word[1] = 0x65;
        test_word[2] = 0x71;
        test_word[3] = 0x1B;

        printf("----Testing exponentiation starting from 1----\n01 ");
        x = 1;
        for (i = 0; i < 20; i++)
            printf("%02X ", x = AES_exp_2(x));
        printf("\n\n\n");

        printf("----Testing key expansion----\n");
        printf("AES128 expanded key\n");
        AES_key_expansion(AES128, AES128_expanded_key, AES128_user_key);
        print_expanded_key(AES128, AES128_expanded_key);
        printf("AES192 expanded key\n");
        AES_key_expansion(AES192, AES192_expanded_key, AES192_user_key);
        print_expanded_key(AES192, AES192_expanded_key);
        printf("AES256 expanded key\n");
        AES_key_expansion(AES256, AES256_expanded_key, AES256_user_key);
        print_expanded_key(AES256, AES256_expanded_key);
        printf("\n");

        printf("----Testing substitute bytes----\n");
        printf("Original\n");
        print_block(test_cols);
        AES_sub_bytes(test_cols, false);
        printf("Sub bytes\n");
        print_block(test_cols);
        AES_sub_bytes(test_cols, true);
        printf("Inverse sub bytes should be same as original\n");
        print_block(test_cols);
        printf("\n");

        printf("----Testing shift rows----\n");
        printf("Original\n");
        print_block(test_cols);
        AES_shift_rows(test_cols, false);
        printf("Shift rows\n");
        print_block(test_cols);
        AES_shift_rows(test_cols, true);
        printf("Inverse shift rows should be same as original\n");
        print_block(test_cols);
        printf("\n");

        printf("----Testing dot product----\n");
        printf("57 dot 83 = ");
        x = AES_dot_product(0x57, 0x83);
        printf("%02X\n", x);
        printf("83 dot 57 = ");
        x = AES_dot_product(0x83, 0x57);
        printf("%02X\n\n\n", x);

        printf("----Testing mix cols----\n");
        printf("Original\n");
        print_block(test_cols);
        AES_mix_cols(test_cols, false);
        printf("Mix cols\n");
        print_block(test_cols);
        AES_mix_cols(test_cols, true);
        printf("Inverse mix cols should be same as original\n");
        print_block(test_cols);
        printf("\n");

        printf("----Testing add round key----\n");
        printf("Original\n");
        print_block(test_cols);
        AES_add_round_key(test_cols, AES128_expanded_key, 0);
        printf("Key added\n");
        print_block(test_cols);
        AES_add_round_key(test_cols, AES128_expanded_key, 0);
        printf("Key added again should be same as original\n");
        print_block(test_cols);
        printf("\n");

        printf("----Testing AES128----\n");
        printf("Original\n");
        print_block(test_cols);
        AES_encrypt(AES128, test_cols, AES128_expanded_key);
        printf("Encrypted\n");
        print_block(test_cols);
        AES_decrypt(AES128, test_cols, AES128_expanded_key);
        printf("Decrypted should be same as before\n");
        print_block(test_cols);
        printf("\n");

        printf("----Testing AES192----\n");
        printf("Original\n");
        print_block(test_cols);
        AES_encrypt(AES192, test_cols, AES192_expanded_key);
        printf("Encrypted\n");
        print_block(test_cols);
        AES_decrypt(AES192, test_cols, AES192_expanded_key);
        printf("Decrypted should be same as before\n");
        print_block(test_cols);
        printf("\n");

        printf("----Testing AES256----\n");
        printf("Original\n");
        print_block(test_cols);
        AES_encrypt(AES256, test_cols, AES256_expanded_key);
        printf("Encrypted\n");
        print_block(test_cols);
        AES_decrypt(AES256, test_cols, AES256_expanded_key);
        printf("Decrypted should be same as before\n");
        print_block(test_cols);

        return EXIT_SUCCESS;
        // */ **** TESTING PURPOSES ****
    }

    if (method) // CFB mode
    {
        if (operation) // Decrypt
        {
            // Print the input
            printf("Input (HEX):\n");
            print_c_string(message, message_len, true);
            printf("\n\n");

            // Decrypt the input with CFB and print
            CFB_decrypt(mode, message, message_len, IV, user_key);
            printf("Decrypted (ASCII):\n");
            print_c_string(message, message_len, false);
            printf("\n\n");
        } else // Encrypt
        {
            // Print the input
            printf("Input (ASCII):\n");
            print_c_string(message, message_len, false);
            printf("\n\n");

            // Encrypt the input with CFB and print
            CFB_encrypt(mode, message, message_len, IV, user_key);
            printf("Encrypted (HEX):\n");
            print_c_string(message, message_len, true);
            printf("\n\n");
        }
    } else // CBC mode
    {
        if (operation) // Decrypt
        {
            // Print the input
            printf("Input (HEX):\n");
            print_c_string(message, message_len, true);
            printf("\n\n");

            // Determine the number of blocks
            int num_blocks = message_len / 16;
            if (message_len % 16 != 0)
                num_blocks++;

            // Process all the blocks from the message
            int state_array[MAX_REQ_LEN / 16][4][4];
            int message_pos = 0;
            int current_block;
            for (current_block = 0; current_block < num_blocks; current_block++)
            {
                char_blockify(message, state_array[current_block], message_pos);
                message_pos += 16;
            }

            // Decrypt the input with CBC and print
            CBC_decrypt(AES128, state_array, num_blocks, IV, user_key);
            message_pos = 0;
            for (current_block = 0; current_block < num_blocks; current_block++)
            {
                char_unblockify(message, state_array[current_block], message_pos);
                message_pos += 16;
            }

            printf("Decrypted (ASCII):\n");
            print_c_string(message, message_len, true);
            printf("\n\n");
        } else // Encrypt
        {
            // Print the input
            printf("Input (ASCII):\n");
            print_c_string(message, message_len, false);
            printf("\n\n");

            // Determine the number of blocks
            int num_blocks = message_len / 16;
            if (message_len % 16 != 0)
                num_blocks++;

            // Process all the blocks from the message
            int state_array[MAX_REQ_LEN / 16][4][4];
            int message_pos = 0;
            int current_block;
            for (current_block = 0; current_block < num_blocks; current_block++)
            {
                char_blockify(message, state_array[current_block], message_pos);
                message_pos += 16;
            }

            // Encrypt the input with CBC and print
            CBC_encrypt(mode, state_array, num_blocks, IV, user_key);
            message_pos = 0;
            for (current_block = 0; current_block < num_blocks; current_block++)
            {
                char_unblockify(message, state_array[current_block], message_pos);
                message_pos += 16;
            }

            printf("Encrypted (HEX):\n");
            print_c_string(message, message_len, true);
            printf("\n\n");
        }
    }

    free(user_key);

    return EXIT_SUCCESS;
}


// Convert a char array to 4x4 block of hex
void char_blockify(unsigned char message[], int state_output[4][4], int start_pos)
{
    int byte_pos = start_pos;
    int row, col;
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            state_output[row][col] = message[byte_pos++];
    }
}


// Convert an integer array to 4x4 block of hex
void hex_blockify(int message[16], int state_output[4][4])
{
    int row, col;
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            state_output[row][col] = message[row + (4 * col)];
    }
}


// Output a word to the terminal
void print_word(int word[], int length)
{
    int i;
    for (i = 0; i < length; i++)
        printf("%02X ", word[i]);
    printf("\n");
}


// Output a 4x4 block to the terminal as a block of hex
void print_block(int state_output[4][4])
{
    int row;
    for (row = 0; row < 4; row++)
        print_word(state_output[row], 4);
    printf("\n");
}


// Output the expanded key in rows of 16
void print_expanded_key(int mode, int expanded_key[])
{
    int key_size;

    if (mode == AES128)
        key_size = AES128_KEY_SIZE;
    else if (mode == AES192)
        key_size = AES192_KEY_SIZE;
    else if (mode == AES256)
        key_size = AES256_KEY_SIZE;
    else
        return;

    int i;
    for (i = 0; i < key_size; i += 16)
        print_word(expanded_key + i, 16);
    printf("\n");
}


// Print a c-string up to a certain length
void print_c_string(unsigned char message[], int message_len, bool hex)
{
    int i;
    for (i = 0; i < message_len; i++)
    {
        if (hex) // Print as hexadecimal
            printf("%02X", message[i]);
        else // Print as ASCII character
            printf("%c", message[i]);
    }
}


// Convert block back to c-string
void char_unblockify(unsigned char message[], int state_output[4][4], int start_pos)
{
    int byte_pos = start_pos;
    int row, col;
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            message[byte_pos++] = state_output[row][col];
    }
}


// Shift first items in an array to the back or vice-versa
void AES_word_rotate(int word[], int length, int rotations, bool inverse)
{
    int old[length];
    int pivot = length - rotations;

    int i;
    for (i = 0; i < length; i++) // Set the old values aside for retrieval
        old[i] = word[i];

    if (inverse) // Shift items in the back to the front
    {
        for (i = 0; i < pivot; i++) // Populate the back with the items from the front
            word[i + rotations] = old[i];

        for (i = pivot; i < length; i++) // Populate the front with the other values from the back
            word[i - pivot] = old[i];
    } else // Shift the items in the front to the back
    {
        for (i = 0; i < pivot; i++) // Populate the front with the items from the back
            word[i] = old[i + rotations];

        for (i = pivot; i < length; i++) // Populate the back with the other values at the front
            word[i] = old[i - pivot];
    }
}


// Divide value up into its MSB and LSB Nibble and return the s_box value
int AES_s_box_transform(int input, bool inverse)
{   //           0 or 1      MSB             LSB
    return S_BOX[inverse][input >> 4][input & 0b00001111];
}


// Core key operation, transform of previous 4 bytes
void AES_key_scheduler(int temp[4], int rcon)
{
    int byte_pos;
    AES_word_rotate(temp, 4, 1, false); // Rotate the word
    for (byte_pos = 0; byte_pos < 4; byte_pos++) // Take the S-transform of the word
        temp[byte_pos] = AES_s_box_transform(temp[byte_pos], false);
    temp[0] ^= rcon; // Add the round constant
}


// Exponentiation of 2, double the previous value except when 0x80 and max value of 0xFF
int AES_exp_2(int previous)
{
    if (previous == 0x80)
        return 0x1B;
    else if (previous * 2 >= 0xFF)
        return 0xFF;
    else
        return previous * 2;
}


// Main key expansion function
void AES_key_expansion(int mode, int expanded_key[], int user_key[])
{
    int user_key_size;
    int expansion;
    int sub_expansion;

    if (mode == AES128)
    {
        expansion = AES128_EXPANSION;
        sub_expansion = AES128_SUB_EXPANSION;
        user_key_size = AES128_USER_KEY_SIZE;
    } else if (mode == AES192)
    {
        expansion = AES192_EXPANSION;
        sub_expansion = AES192_SUB_EXPANSION;
        user_key_size = AES192_USER_KEY_SIZE;
    } else if (mode == AES256)
    {
        expansion = AES256_EXPANSION;
        sub_expansion = AES256_SUB_EXPANSION;
        user_key_size = AES256_USER_KEY_SIZE;
    } else
        return;

    int byte_pos;
    int temp[4];

    // Set first x bytes as the user key
    int key_pos;
    for (key_pos = 0; key_pos < user_key_size; key_pos++)
        expanded_key[key_pos] = user_key[key_pos];

    // Last 4 bits into temp
    for (key_pos = 0; key_pos < 4; key_pos++)
        temp[key_pos] = user_key[user_key_size - (4 - key_pos)];

    // Fill the expanded key until the required length is reached
    int expanded_pos;
    int sub_pos;
    int rcon  = 1;
    for (expanded_pos = 0; expanded_pos < expansion; expanded_pos++)
    {
        AES_key_scheduler(temp, rcon);
        rcon = AES_exp_2(rcon);

        for (byte_pos = 0; byte_pos < 4; byte_pos++)
        {
            temp[byte_pos] ^= expanded_key[byte_pos + (user_key_size * expanded_pos)]; // Bitwise XOR with x bytes before
            expanded_key[byte_pos + user_key_size + (user_key_size * expanded_pos)] = temp[byte_pos]; // Expand key
        }

        // Perform the sub-expansion
        for (sub_pos = 0; sub_pos < sub_expansion; sub_pos++)
        {
            for (byte_pos = 0; byte_pos < 4; byte_pos++)
            {
                temp[byte_pos] ^= expanded_key[byte_pos + 4 + (user_key_size * expanded_pos) + (4 * sub_pos)]; // Bitwise XOR with x bytes before
                expanded_key[byte_pos + 4 + user_key_size + (user_key_size * expanded_pos) + (4 * sub_pos)] = temp[byte_pos]; // Expand key
            }
        }
    }
}


// Substitute a block through the S-transform
void AES_sub_bytes(int state_output[4][4], bool inverse)
{
    int row, col;
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++) // Perform S-transform on every byte
            state_output[row][col] = AES_s_box_transform(state_output[row][col], inverse);
    }
}


// The AES row shifting function
void AES_shift_rows(int state_output[4][4], bool inverse)
{
    /*
     * Rotate each word by the number of times equal to its index, i.e.
     * Row 0 stays the same
     * Row 1 is shifted once
     * Row 2 is shifted twice
     * Row 3 is shifted thrice
     */

    int row;
    for (row = 1; row < 4; row++)
        AES_word_rotate(state_output[row], 4, row, inverse);
}


// Finite field multiplication according to AES reference manual
int AES_dot_product(int a, int b)
{
    /*
     * Represent both numbers as polynomials, i.e.
     * 0b00000000 = 0
     * 0b00000001 = 1
     * 0b00000010 = x
     * 0b00000100 = x^2
     * ...
     * 0b1...     = x^n
     *
     * XOR pairs to put together, i.e.
     * 0b101101 = x^5 + x^3 + x^2 + 1
     */
    
    int i;
    int result = 0;

    // Expand polynomial
    /*
     * (polynomial a) * (polynomial b)
     * Multiplying a polynomial by x^n is equal to a n left shift
     * XOR the resulting polynomials together
     */
    int position = 128; // = 2^7 = 0b10000000 => x^7
    for (i = 7; i >= 0; i--)
    {
        if ((a & position) == position) // See if (a) has the power of x currently looked at
            result ^= b << i; // Shift (b) left by the power of x currently looked at if present
        position = position >> 1; // Make power of x one smaller
    }

    if (result < 0xFF) // Already smaller, modulo is the result
        return result;

    // Calculate modulo
    // Polynomial long division with irreducible polynomial x^8 + x^4 + x^3 + x + 1 => 0b100011011
    position = 65536; // = 2^16 = 0b1000000000000000 => x^16
    for (i = 16; i > 7; i--)
    {
        if ((result & position) == position) // See if (result) has the power of x currently looked at
            result ^= 0b100011011 << (i - 8); // Subtract a multiple of the irreducible polynomial if present
        position = position >> 1; // Make power of x one smaller
    }

    return result; // Remainder after long division was done
}


// Recursive multiplication of the column value and prime matrix
//int AES_dot_product(int prime, int current) // Checked
//{
//    if (prime == 2)
//    {
//        bool flag = current > 127;
//        current = (current << 1) & 0b011111111;
//        if (flag)
//            return current ^ 0b00011011;
//        else
//            return current;
//    } else if (prime == 3) // 2 + 1 = 3
//        return AES_dot_product(2, current) ^ current;
//    else if (prime == 9) // 2 x 2 x 2 + 1 = 9
//        return AES_dot_product(2, AES_dot_product(2, AES_dot_product(2, current))) ^ current;
//    else if (prime == 11) // 2 x (2 x 2 + 1) + 1 = 11
//        return AES_dot_product(2, AES_dot_product(2, AES_dot_product(2, current)) ^ current) ^ current;
//    else if (prime == 13) // 2 x 2 x (2 + 1) + 1 = 13
//        return AES_dot_product(2, AES_dot_product(2, AES_dot_product(2, current) ^ current)) ^ current;
//    else if (prime == 14) // 2 x ((2 x (2 + 1) + 1) = 14
//        return AES_dot_product(2, AES_dot_product(2, AES_dot_product(2, current) ^ current) ^ current);
//    else // prime == 1
//        return current;
//}


// Perform the dot product of the block and the prime matrix
void AES_mix_cols(int state_output[4][4], bool inverse)
{
    // Matrix dot operation with the prime matrix
    int row, col, out;
    int new_state[4][4];
    int multiply[4];
    for (out = 0; out < 4; ++out)
    {
        for (row = 0; row < 4; row++)
        {
            for (col = 0; col < 4; col++) // Calculate sub dot products
                multiply[col] = AES_dot_product(PRIME_MATRIX[inverse][row][col], state_output[col][out]);
            new_state[row][out] = multiply[0] ^ multiply[1] ^ multiply[2] ^ multiply[3]; // Add sub dot products together
        }
    }

    // Copy the result over the input as output
    for (row = 0; row < 4; row++)
    {
        for (col = 0; col < 4; col++)
            state_output[row][col] = new_state[row][col];
    }
}


// XOR a block with the expanded key at a certain index
void AES_add_round_key(int state_output[4][4], int expanded_key[], int key_index)
{
    int col, row;
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++) // Do column wise XOR with the matching index of the key
            state_output[row][col] ^= expanded_key[row + (col * 4) + key_index];
    }
}


// The AES encryption algorithm
bool AES_encrypt(int mode, int state_output[4][4], int expanded_key[])
{
    int number_of_rounds;

    if (mode == AES128)
        number_of_rounds = AES128_ROUNDS;
    else if (mode == AES192)
        number_of_rounds = AES192_ROUNDS;
    else if (mode == AES256)
        number_of_rounds = AES256_ROUNDS;
    else
        return EXIT_FAILURE;

    int key_index = 0; // Start at the beginning of the key and work forwards

    // Initial round, add round key
    AES_add_round_key(state_output, expanded_key, key_index);

    // Perform the normal rounds
    int round;
    for (round = 0; round < number_of_rounds - 1; round++)
    {
        key_index += 16; // Move to next section
        AES_sub_bytes(state_output, false); // Substitute bytes
        AES_shift_rows(state_output, false); // Shift rows
        AES_mix_cols(state_output, false); // Mix columns
        AES_add_round_key(state_output, expanded_key, key_index); // Add round key
    }

    // Last round is a special case
    key_index += 16; // Move to the last section
    AES_sub_bytes(state_output, false); // Substitute bytes
    AES_shift_rows(state_output, false); // Shift rows
    AES_add_round_key(state_output, expanded_key, key_index); // Add round key
    // No mix columns

    return EXIT_SUCCESS;
}


// The AES decryption algorithm
bool AES_decrypt(int mode, int state_output[4][4], int expanded_key[])
{
    int number_of_rounds;
    int key_size;

    if (mode == AES128)
    {
        number_of_rounds = AES128_ROUNDS;
        key_size = AES128_KEY_SIZE;
    } else if (mode == AES192)
    {
        number_of_rounds = AES192_ROUNDS;
        key_size = AES192_KEY_SIZE;
    } else if (mode == AES256)
    {
        number_of_rounds = AES256_ROUNDS;
        key_size = AES256_KEY_SIZE;
    } else
        return EXIT_FAILURE;

    int key_index = key_size - 16; // Start at the end of the key and work backwards

    // Initial round, add round key
    AES_add_round_key(state_output, expanded_key, key_index);

    // Perform the normal rounds
    int round;
    for (round = 0; round < number_of_rounds - 1; round++)
    {
        key_index -= 16; // Move to previous section
        AES_shift_rows(state_output, true); // Inverse shift rows
        AES_sub_bytes(state_output, true); // Inverse substitute bytes
        AES_add_round_key(state_output, expanded_key, key_index); // Add round key
        AES_mix_cols(state_output, true); // Inverse mix columns
    }

    // Last round is a special case
    key_index -= 16; // Move to the first section
    AES_shift_rows(state_output, true); // Inverse shift rows
    AES_sub_bytes(state_output, true); // Inverse substitute bytes
    AES_add_round_key(state_output, expanded_key, key_index); // Add round key
    // No mix columns

    return EXIT_SUCCESS;
}


// The Cipher Block Chaining encryption
bool CBC_encrypt(int mode, int state_output_blocks[][4][4], int num_blocks, int IV[16], int user_key[])
{
    int key_size;
    
    if (mode == AES128)
        key_size = AES128_KEY_SIZE;
    else if (mode == AES192)
        key_size = AES192_KEY_SIZE;
    else if (mode == AES256)
        key_size = AES256_KEY_SIZE;
    else
        return EXIT_FAILURE;
    
    int expanded_key[key_size];
    AES_key_expansion(mode, expanded_key, user_key);
    
    int row, col, i;
    int current_vector[16];

    // Copy IV to not change its contents
    for (i = 0; i < 16; i ++)
        current_vector[i] = IV[i];

    int block_pos;
    for (block_pos = 0; block_pos < num_blocks; block_pos++)
    {
        // XOR current vector with plaintext
        for (col = 0; col < 4; col++)
        {
            for (row = 0; row < 4; row++)
                state_output_blocks[block_pos][row][col] ^= current_vector[row + (col * 4)];
        }

        // Encrypt to produce ciphertext block
        AES_encrypt(mode, state_output_blocks[block_pos], expanded_key);

        // Update current vector with ciphertext values
        for (col = 0; col < 4; col++)
        {
            for (row = 0; row < 4; row++)
                current_vector[row + (col * 4)] = state_output_blocks[block_pos][row][col];
        }
    }

    return EXIT_SUCCESS;
}


// The Cipher Block Chaining decryption
bool CBC_decrypt(int mode, int state_output_blocks[][4][4], int num_blocks, int IV[16], int user_key[])
{
    int key_size;

    if (mode == AES128)
        key_size = AES128_KEY_SIZE;
    else if (mode == AES192)
        key_size = AES192_KEY_SIZE;
    else if (mode == AES256)
        key_size = AES256_KEY_SIZE;
    else
        return EXIT_FAILURE;

    int expanded_key[key_size];
    AES_key_expansion(mode, expanded_key, user_key);
    
    int i, row, col;
    int previous_ciphertext[16];
    int current_vector[16];

    // Copy IV to not change its contents
    for (i = 0; i < 16; i++)
        current_vector[i] = IV[i];

    int block_pos;
    for (block_pos = 0; block_pos < num_blocks; block_pos++)
    {
        // Copy current ciphertext values
        for (col = 0; col < 4; col++)
        {
            for (row = 0; row < 4; row++)
                previous_ciphertext[row + (col * 4)] = state_output_blocks[block_pos][row][col];
        }

        // Decrypt the block
        AES_decrypt(mode, state_output_blocks[block_pos], expanded_key);

        // XOR current vector with decrypted text to produce plaintext
        for (col = 0; col < 4; col++)
        {
            for (row = 0; row < 4; row++)
                state_output_blocks[block_pos][row][col] ^= current_vector[row + (col * 4)];
        }

        // Update the current vector with previous ciphertext values
        for (i = 0; i < 16; i++)
            current_vector[i] = previous_ciphertext[i];
    }

    return EXIT_SUCCESS;
}


// The Cipher Feedback encryption algorithm
bool CFB_encrypt(int mode, unsigned char message[], int message_len, int IV[16], int user_key[])
{
    int key_size;

    if (mode == AES128)
        key_size = AES128_KEY_SIZE;
    else if (mode == AES192)
        key_size = AES192_KEY_SIZE;
    else if (mode == AES256)
        key_size = AES256_KEY_SIZE;
    else
        return EXIT_FAILURE;

    int expanded_key[key_size];
    AES_key_expansion(mode, expanded_key, user_key);

    int i;
    int current_block[4][4];
    int current_vector[16]; // AES requires 128 bit input even though a character in the stream is only 8 bits

    // Copy IV to not change its contents
    for (i = 0; i < 16; i++)
        current_vector[i] = IV[i];

    int message_pos;
    for (message_pos = 0; message_pos < message_len; message_pos++)
    {
        // Convert the encryption input to a block
        hex_blockify(current_vector, current_block);

        // Encrypt the block
        AES_encrypt(mode, current_block, expanded_key);

        // Take first byte in the block and XOR with the plaintext byte to get the ciphertext byte
        message[message_pos] ^= current_block[0][0]; 
        // Discard the rest of the block (a bit wasteful)

        // Shift the current vector to the left by one byte
        AES_word_rotate(current_vector, 16, 1, false);
        // Put the ciphertext byte in the last byte
        current_vector[15] = message[message_pos];
    }

    return EXIT_SUCCESS;
}


// The Cipher Feedback decryption algorithm
bool CFB_decrypt(int mode, unsigned char message[], int message_len, int IV[16], int user_key[])
{
    int key_size;

    if (mode == AES128)
        key_size = AES128_KEY_SIZE;
    else if (mode == AES192)
        key_size = AES192_KEY_SIZE;
    else if (mode == AES256)
        key_size = AES256_KEY_SIZE;
    else
        return EXIT_FAILURE;

    int expanded_key[key_size];
    AES_key_expansion(mode, expanded_key, user_key);

    int i;
    int current_block[4][4];
    int current_vector[16]; // AES requires 128 bit input even though a character in the stream is only 8 bits

    // Copy IV to not change its contents
    for (i = 0; i < 16; i++)
        current_vector[i] = IV[i];

    int message_pos;
    for (message_pos = 0; message_pos < message_len; message_pos++)
    {
        // Convert the encryption input to a block
        hex_blockify(current_vector, current_block);

        // Encrypt the block
        AES_encrypt(mode, current_block, expanded_key);

        // Shift the current vector to the left by one byte
        AES_word_rotate(current_vector, 16, 1, false);
        // Put the ciphertext byte in the last byte
        current_vector[15] = message[message_pos];

        // Take first byte in the block and XOR with the ciphertext byte to get the plaintext byte
        message[message_pos] ^= current_block[0][0];
        // Discard the rest of the block (a bit wasteful)
    }

    return EXIT_SUCCESS;
}
