#include "Encryption.h"


int main(int argc, char *argv[])
{
    int i;
    int message_len;
    int num_blocks;
    int current_block = 0;
    int message_pos = 0;
    int state_array[MAX_REQ_LEN / 16][4][4];
    char message[MAX_REQ_LEN];

    int AES128_user_key[AES128_USER_KEY_SIZE] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F,
                                                 0x6E, 0x61, 0x6C, 0x69};
    int AES192_user_key[AES192_USER_KEY_SIZE] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F,
                                                 0x6E, 0x61, 0x6C, 0x69, 0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E};
    int AES256_user_key[AES256_USER_KEY_SIZE] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F,
                                                 0x6E, 0x61, 0x6C, 0x69, 0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E,
                                                 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x61, 0x6C, 0x69};
    int IV[16] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x61, 0x6C, 0x69};


#if DEBUG // TODO: remove when no longer needed
    //    **** TESTING PURPOSES **** /*
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

    printf("\n\n\n");
    // */ **** TESTING PURPOSES ****
#endif


    // Greeting
    printf("EHN 410 Group 12 Practical 2\n\n");

    // To be encrypted
    for (i = 0; i < MAX_REQ_LEN; i++)
        message[i] = '\0';
    strcpy(message, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent sagittis, est sit amet dignissim pretium, justo nulla gravida arcu, et facilisis nisl enim vitae massa. Nulla ac rutrum nisl, et consequat risus. Mauris non arcu vel libero semper.");
//    fgets(message, MAX_REQ_LEN, stdin); // TODO: add this later
    // TODO: ask for CBC or CFB mode

    // Determine the number of blocks
    message_len = strlen(message);
    num_blocks = message_len / 16;
    if (message_len % 16 != 0)
        num_blocks++;

    // Process all the blocks from the message
    printf("Input:\n");
    for (current_block = 0; current_block < num_blocks; current_block++)
    {
        char_blockify(message, state_array[current_block], message_pos);
        message_pos += 16;
        printf("Block %d\n", current_block);
        print_block(state_array[current_block]);
    }
    printf("Input:\n%s\n\n", message);

    CBC_encrypt(AES128, state_array, num_blocks, IV, AES128_user_key);

    printf("CBC encrpyted:\n");
    message_pos = 0;
    for (current_block = 0; current_block < num_blocks; current_block++)
    {
        char_unblockify(message, state_array[current_block], message_pos);
        message_pos += 16;
    }
    message[message_pos] = '\0';
    printf("%s\n\n", message);

    CBC_decrypt(AES128, state_array, num_blocks, IV, AES128_user_key);

    printf("CBC decrpyted:\n");
    message_pos = 0;
    for (current_block = 0; current_block < num_blocks; current_block++)
    {
        char_unblockify(message, state_array[current_block], message_pos);
        message_pos += 16;
    }
    message[message_pos] = '\0';
    printf("%s\n\n", message);
}


// Convert a char array to 4x4 block of hex
void char_blockify(char message[], int state_output[4][4], int start_pos)
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


// Convert block back to c-string
void char_unblockify(char message[], int state_output[4][4], int start_pos)
{
    int byte_pos = start_pos;
    int row, col;
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            message[byte_pos++] = state_output[row][col];
    }
}


// Shift last items in an array to the front or vice-versa
void AES_word_rotate(int word[], int length, int rotations, bool inverse)
{
    int temp[length];
    int pivot = length - rotations;

    int i;
    for (i = 0; i < length; i++)
        temp[i] = word[i];

    if (inverse)
    {
        for(i = pivot; i < length; i++)
            word[i - pivot] = temp[i];

        for(i = 0; i < pivot; i++)
            word[i + rotations] = temp[i];

    } else
    {
        for(i = 0; i < pivot; i++)
            word[i] = temp[i + rotations];

        for(i = pivot; i < length; i++)
            word[i] = temp[i - pivot];
    }
}


// Divide value up into its MSB and LSB Nibble and return the s_box value
int AES_s_box_transform(int input, bool inverse) // Checked
{   //           0 or 1      MSB             LSB
    return S_BOX[inverse][input >> 4][input & 0b00001111];
}


// Core key operation, transform of previous 4 bytes
void AES_key_scheduler(int temp[4], int rcon) // Checked
{
    int byte_pos;
    AES_word_rotate(temp, 4, 1, false); // Rotate the word
    for (byte_pos = 0; byte_pos < 4; byte_pos++) // Take the S-transform of the word
        temp[byte_pos] = AES_s_box_transform(temp[byte_pos], false);
    temp[0] ^= rcon; // Add the round constant
}


// Exponentiation of 2, double the previous value except when 0x80 and max value of 0xFF
int AES_exp_2(int previous) // Checked
{
    if (previous == 0x80)
        return 0x1B;
    else if (previous * 2 >= 0xFF)
        return 0xFF;
    else
        return previous * 2;
}


// Main key expansion function
void AES_key_expansion(int mode, int expanded_key[], int user_key[]) // Checked
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
void AES_sub_bytes(int state_output[4][4], bool inverse) // Checked
{
    int row, col;
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++) // Perform S-transform on every byte
            state_output[row][col] = AES_s_box_transform(state_output[row][col], inverse);
    }
}


// The AES row shifting function
void AES_shift_rows(int state_output[4][4], bool inverse) // Checked
{
    /*
     * Rotate each word by the number of times equal to its index, i.e.
     * Row 0 stays the same
     * Row 1 is shifted once
     * Row 2 is shifted twice
     * Row 3 is shifted three times
     */

    int row;
    for (row = 1; row < 4; row++)
        AES_word_rotate(state_output[row], 4, row, inverse);
}


// Finite field multiplication according to AES reference manual
int AES_dot_product(int a, int b) // Checked
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
     *
     * 0b101110 = x^5 + x^3 + x^2 + x
     */

    int result = 0;
    int position = 128; // = 2^7 = 0b10000000 => x^7
    int i;

    // Expand polynomial
    /*
     * (polynomial a) * (polynomial b)
     * Multiplying a polynomial by x^n is equal to a n left shift
     * XOR the resulting polynomials together
     */
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
        if ((result & position) == position) // Match a multiple of the irreducible polynomial to the result
            result ^= 0b100011011 << (i - 8); // Subtract the multiple if matched
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
//        if(flag)
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
void AES_mix_cols(int state_output[4][4], bool inverse)  // Checked
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
void AES_add_round_key(int state_output[4][4], int expanded_key[], int key_index) // Checked
{
    int col, row;
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++) // Do column wise XOR with the matching index of the key
            state_output[row][col] ^= expanded_key[row + (col * 4) + key_index];
    }
}


// The AES encryption algorithm
bool AES_encrypt(int mode, int state_output[4][4], int expanded_key[]) // Checked
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

    int key_index = 0; // Start at the front of the key and work forwards

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
    key_index += 16; // Move to next section
    AES_sub_bytes(state_output, false); // Substitute bytes
    AES_shift_rows(state_output, false); // Shift rows
    AES_add_round_key(state_output, expanded_key, key_index); // Add round key
    // No mix columns

    return EXIT_SUCCESS;
}


// The AES decryption algorithm
bool AES_decrypt(int mode, int state_output[4][4], int expanded_key[]) // Checked
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

    int key_index = key_size - 16; // Start from the back of the key and work backwards

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
    key_index -= 16; // Move to previous section
    AES_shift_rows(state_output, true); // Inverse shift rows
    AES_sub_bytes(state_output, true); // Inverse substitute bytes
    AES_add_round_key(state_output, expanded_key, key_index); // Add round key
    // No mix columns

    return EXIT_SUCCESS;
}


// The Cipher Block Chaining encryption
bool CBC_encrypt(int mode, int state_output_blocks[][4][4], int num_blocks, int IV[16], int user_key[]) // Checked
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
    for (i = 0; i < 16; i ++) // Copy IV to not change its contents
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

        // Encrypt to produce cipher text
        if (mode == AES128)
            AES_encrypt(AES128, state_output_blocks[block_pos], expanded_key);
        else if (mode == AES192)
            AES_encrypt(AES192, state_output_blocks[block_pos], expanded_key);
        else
            AES_encrypt(AES256, state_output_blocks[block_pos], expanded_key);

        // Update current vector with cipher text values
        for (col = 0; col < 4; col++)
        {
            for (row = 0; row < 4; row++)
                current_vector[row + (col * 4)] = state_output_blocks[block_pos][row][col];
        }
    }

    return EXIT_SUCCESS;
}


// The Cipher Block Chaining decryption
bool CBC_decrypt(int mode, int state_output_blocks[][4][4], int num_blocks, int IV[16], int user_key[]) // Checked
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

    for (i = 0; i < 16; i++) // Copy IV to not change its contents
        current_vector[i] = IV[i];

    int block_pos;
    for (block_pos = 0; block_pos < num_blocks; block_pos++)
    {
        // Copy current cipher text values
        for (col = 0; col < 4; col++)
        {
            for (row = 0; row < 4; row++)
                previous_ciphertext[row + (col * 4)] = state_output_blocks[block_pos][row][col];
        }

        // Decrypt
        if (mode == AES128)
            AES_decrypt(AES128, state_output_blocks[block_pos], expanded_key);
        else if (mode == AES192)
            AES_decrypt(AES192, state_output_blocks[block_pos], expanded_key);
        else 
            AES_decrypt(AES256, state_output_blocks[block_pos], expanded_key);

        // XOR current vector with decrypted text to produce plaintext
        for (col = 0; col < 4; col++)
        {
            for (row = 0; row < 4; row++)
                state_output_blocks[block_pos][row][col] ^= current_vector[row + (col * 4)];
        }

        // Update the current vector with previous cipher text values
        for (i = 0; i < 16; i++)
            current_vector[i] = previous_ciphertext[i];
    }

    return EXIT_SUCCESS;
}


// The Cipher Feedback encryption algorithm
bool CFB_encrypt(int mode, int stream_input[][8], int num_blocks, int IV[16], int user_key[]) // TODO: not tested
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
    int block[4][4];
    int current_vector[16];
    
    // Copy the initialization vector to preserve it
    for (i = 0; i < 16; i++)
        current_vector[i] = IV[i];

    int block_pos;
    for (block_pos = 0; block_pos < num_blocks; block_pos++)
    {
        hex_blockify(current_vector, block);

        // Encrypt
        if (mode == AES128)
            AES_encrypt(AES128, block, expanded_key);
        else if (mode == AES192)
            AES_encrypt(AES192, block, expanded_key);
        else
            AES_encrypt(AES256, block, expanded_key);

        // Move bytes
        for (i = 0; i < 8; i++)
            current_vector[i] = current_vector[i + 8];

        // XOR chain with plaintext
        for (col = 0; col < 2; col++)
        {
            for (row = 0; row < 4; row++)
            {
                stream_input[block_pos][row + (col * 4)] ^= block[row][col];
                current_vector[row + (col * 4) + 8] = stream_input[block_pos][row + (col * 4)];
            }
        }
    }

    return EXIT_SUCCESS;
}


// The Cipher Feedback decryption algorithm
bool CFB_decrypt(int mode, int stream_input[][8], int num_blocks, int IV[16], int user_key[]) // TODO: not tested
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
    int block[4][4];
    int current_vector[16];

    // Copy the initialization vector to preserve it
    for (i = 0; i < 16; i++)
        current_vector[i] = IV[i];

    int block_pos;
    for (block_pos = 0; block_pos < num_blocks; block_pos++)
    {
        hex_blockify(current_vector, block);

        // Decrypt
        if (mode == AES128)
            AES_decrypt(AES128, block, expanded_key);
        else if (mode == AES192)
            AES_decrypt(AES192, block, expanded_key);
        else
            AES_decrypt(AES256, block, expanded_key);

        // Move bytes
        for (i = 0; i < 8; i++)
            current_vector[i] = current_vector[i + 8];

        // XOR chain with plaintext
        for (col = 0; col < 2; col++)
        {
            for (row = 0; row < 4; row++)
            {
                current_vector[row + (col * 4) + 8] = stream_input[block_pos][row + (col * 4)];
                stream_input[block_pos][row + (col * 4)] ^= block[row][col];
            }
        }
    }

    return EXIT_SUCCESS;
}
