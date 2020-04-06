#include "Encryption.h"


int main(int argc, char *argv[])
{
    int i;
    int message_len;
    int num_blocks;
//    int padding_pos;
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
    int AES128_expanded_key[AES128_KEY_SIZE];
    int AES192_expanded_key[AES192_KEY_SIZE];
    int AES256_expanded_key[AES256_KEY_SIZE];

    //    **** TESTING PURPOSES **** /*
    // TODO: remove when no longer needed
    int test[4] = {0x3A, 0x65, 0x71, 0x1B};
    int key_example[16] = {0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0x00, 0xaf, 0x7f, 0x67, 0x98};
    int test_cols[4][4] = {{0x74, 0x20, 0x61, 0x73},
                           {0x68, 0x69, 0x20, 0x74},
                           {0x69, 0x73, 0x74, 0x2e},
                           {0x73, 0x20, 0x65, 0x2e}};

    AES_mix_cols(test_cols, false);
    print_block(test_cols);
    AES_mix_cols(test_cols, true);

    AES_shift_rows(test_cols, false);
    AES_shift_rows(test_cols, true);

    AES_key_expansion(AES128, AES128_expanded_key, AES128_user_key);
//    for (i = 0; i < 176; i++)
//    {
//        printf("%02X ", AES128_expanded_key[i]);
//        if ((i + 1) % 16 == 0)
//            printf("\n");
//    }
    AES_key_expansion(AES192, AES192_expanded_key, AES192_user_key);
    AES_key_expansion(AES256, AES256_expanded_key, AES256_user_key);

    int a = AES_s_box_transform(0x3a, false);
    a = AES_s_box_transform(a, true);
    // */ **** TESTING PURPOSES ****

    // Greeting
    printf("EHN 410 Group 12 Practical 2\n\n");

    // To be encrypted
    for (i = 0; i < MAX_REQ_LEN; i++)
        message[i] = '\0';
    strcpy(message, "test functionality");
//    fgets(message, MAX_REQ_LEN, stdin); // TODO: add this later
    message_len = strlen(message);
    num_blocks = message_len / 16;
    if (message_len % 16 != 0)
        num_blocks++;

    // Process all the blocks from the message
    for (current_block = 0; current_block < num_blocks; current_block++)
    {
        char_blockify(message, state_array[current_block], message_pos);
        message_pos += 16;
        printf("Block %d\n", current_block);
        print_block(state_array[current_block]);
    }

    //    **** TESTING PURPOSES **** /*
    // TODO: fix
    printf("Before\n");
    print_block(state_array[0]);
    AES_encrypt(AES128, state_array[0], AES128_expanded_key);
    AES_decrypt(AES128, state_array[0], AES128_expanded_key);
    printf("After (should be same as before)\n");
    print_block(state_array[0]);
    // */ **** TESTING PURPOSES ****
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
            state_output[row][col] = message[(4 * col) + row];
    }
}


// Output a 4x4 block to the terminal as a block of hex
void print_block(int state_output[4][4])
{
    int row, col;
    for (row = 0; row < 4; row++)
    {
        for (col = 0; col < 4; col++)
        {
            printf("%02X", state_output[row][col]);
            printf(" ");
        }
        printf("\n");
    }
    printf("\n");
}


// Shift last item in an array to the front
void AES_word_rotate_32(int word[4], bool inverse) // Checked
{
    if (inverse)
    {   // Shift last item to front
        int temp = word[0];
        word[0] = word[3];
        word[3] = word[2];
        word[2] = word[1];
        word[1] = temp;
    } else
    {   // Shift first item to back
        int temp = word[3];
        word[3] = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = temp;
    }
}


// Divide value up into its MSB and LSB Nibble and return the s_box value
int AES_s_box_transform(int input, bool inverse)
{
    return s_box[inverse][input >> 4][input & 0b00001111];
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


// Core key operation, transform of previous 4 bytes
void AES_key_scheduler(int temp[4], int rcon) // Checked
{
    int byte_pos;
    AES_word_rotate_32(temp, false);
    for (byte_pos = 0; byte_pos < 4; byte_pos++)
        temp[byte_pos] = AES_s_box_transform(temp[byte_pos], false);
    temp[0] ^= rcon;
}


// Main key expansion function
void AES_key_expansion(int mode, int expanded_key[], int user_key[]) // Checked for 128
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

    // Set first x bytes user key
    int key_pos;
    for (key_pos = 0; key_pos < user_key_size; key_pos++)
        expanded_key[key_pos] = user_key[key_pos];

    // Last 4 bits into temp
    for (key_pos = 0; key_pos < 4; key_pos++)
        temp[key_pos] = user_key[user_key_size - (4 - key_pos)];

//    key_scheduler(temp, rcon);
//    rcon++;
//
//    for (byte_pos = 0; byte_pos < 4; byte_pos++)
//    {
//        temp[byte_pos] ^= aes_key[byte_pos]; // Bitwise XOR with x bytes before
//        aes_key[byte_pos+16] = temp[byte_pos]; // Expand key
//    }

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


// The AES row shifting function
void AES_shift_rows(int state_output[4][4], bool inverse) // Checked
{
    int row;
    int num_rotations;
    for (row = 1; row < 4; row++)
    {
        for (num_rotations = 0; num_rotations < row; num_rotations++)
            AES_word_rotate_32(state_output[row], inverse);
    }
}


// Recursive multiplication of the column value and prime matrix
int AES_matrix_dot(int prime, int current) // Checked
{
    // Well done Ivan, die is net beautiful
    if (prime == 2)
    {
        current = (current << 1) & 0b011111111;
        if((current & 0b10000000) == 0b10000000)
            return current ^ 0b00011011;
        else
            return current;
    } else if (prime == 3) // 2 + 1 = 3
        return AES_matrix_dot(2, current) ^ current;
    else if (prime == 9) // 2 x 2 x 2 + 1 = 9
        return AES_matrix_dot(2, AES_matrix_dot(2, AES_matrix_dot(2, current))) ^ current;
    else if (prime == 11) // 2 x (2 x 2 + 1) + 1 = 11
        return AES_matrix_dot(2, AES_matrix_dot(2, AES_matrix_dot(2, current)) ^ current) ^ current;
    else if (prime == 13) // 2 x 2 x (2 + 1) + 1 = 13
        return AES_matrix_dot(2, AES_matrix_dot(2, AES_matrix_dot(2, current) ^ current)) ^ current;
    else if (prime == 14) // 2 x ((2 x (2 + 1) + 1) = 14
        return AES_matrix_dot(2, AES_matrix_dot(2, AES_matrix_dot(2, current) ^ current) ^ current);
    else // prime == 1
        return current;
}


// Perform the dot product of the block and the prime matrix
void AES_mix_cols(int state_output[4][4], bool inverse) // TODO: not returning correct result
{
    int row, col, out;
    int new_state[4][4];
    int multiply[4];
    for (out = 0; out < 4; ++out)
    {
        for (row = 0; row < 4; row++)
        {
            for (col = 0; col < 4; col++)
                multiply[col] = AES_matrix_dot(prime_matrix[inverse][row][col], state_output[col][out]);
            new_state[row][out] = multiply[0] ^ multiply[1] ^ multiply[2] ^ multiply[3];
        }
    }

    for (row = 0; row < 4; row++)
    {
        for (col = 0; col < 4; col++)
            state_output[row][col] = new_state[row][col];
    }
}


// Perform one round of the AES algorithm
void AES_round(int state_output[4][4], int expanded_key[], int key_index, bool mix_cols, bool inverse) // TODO: check
{
    // Substitute bytes
    int row, col;
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            state_output[row][col] = AES_s_box_transform(state_output[row][col], inverse);
    }

    // Shift rows
    AES_shift_rows(state_output, inverse);

    // Mix columns
    if (mix_cols)
        AES_mix_cols(state_output, inverse);

    // Add round key
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            state_output[row][col] ^= expanded_key[row + (col * 4) + key_index];
    }
}


// The AES encryption algorithm
bool AES_encrypt(int mode, int state_output[4][4], int expanded_key[]) // TODO: compare with known result
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

    int row, col;
    int key_index = 0;

    // Initial round, add round key
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            state_output[row][col] ^= expanded_key[row + (col * 4) + key_index];
    }

    // Perform the normal rounds
    int round;
    for (round = 0; round < number_of_rounds - 1; round++)
    {
        key_index += 16; // Update key position
        AES_round(state_output, expanded_key, key_index, true, false); // Perform a normal AES round
    }

    // Last round is a special case
    key_index += 16; // Update key position
    AES_round(state_output, expanded_key, key_index, false, false); // Perform a last AES round

    return EXIT_SUCCESS;
}


// The AES decryption algorithm
bool AES_decrypt(int mode, int state_output[4][4], int expanded_key[]) // TODO: decrypt not yielding plaintext as expected
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

    int row, col;

    // First round is a special case
    int key_index = key_size - 16; // Update key position
    AES_round(state_output, expanded_key, key_index, false, true); // Perform a first AES round

    // Perform the normal rounds
    int round;
    for (round = 0; round < number_of_rounds - 1; round++)
    {
        key_index -= 16; // Update key position
        AES_round(state_output, expanded_key, key_index, true, true); // Perform a normal AES round
    }

    // Last round, add round key
    key_index -= 16; // Update key position
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            state_output[row][col] ^= expanded_key[row + (col * 4) + key_index];
    }

    return EXIT_SUCCESS;
}


// The Cipher Block Chaining encryption
bool CBC_encrypt(int mode, int state_output_blocks[][4][4], int num_blocks, int IV[16], int user_key[]) // TODO: not tested
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
    
    int row, col;

    int block_pos;
    for (block_pos = 0; block_pos < num_blocks; block_pos++)
    {
        // XOR chain with plaintext
        for (col = 0; col < 4; col++)
        {
            for (row = 0; row < 4; row++)
                state_output_blocks[block_pos][row][col] ^= IV[row + (col * 4)];
        }

        // Encrypt
        if (mode == AES128)
            AES_encrypt(AES128, state_output_blocks[block_pos], expanded_key);
        else if (mode == AES192)
            AES_encrypt(AES192, state_output_blocks[block_pos], expanded_key);
        else
            AES_encrypt(AES256, state_output_blocks[block_pos], expanded_key);

        // Update chain with cipher text values
        for (col = 0; col < 4; col++)
        {
            for (row = 0; row < 4; row++)
                IV[row + (col * 4)] = state_output_blocks[block_pos][row][col];
        }
    }

    return EXIT_SUCCESS;
}


// The Cipher Block Chaining decryption
bool CBC_decrypt(int mode, int state_output_blocks[][4][4], int num_blocks, int IV[16], int user_key[]) // TODO: not tested
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
    
    int row, col;
    int chain_pos;
    int chain[16];

    int block_pos;
    for (block_pos = 0; block_pos < num_blocks; block_pos++)
    {
        // Update chain with cipher text values
        for (col = 0; col < 4; col++)
        {
            for (row = 0; row < 4; row++)
                chain[row + (col * 4)] = state_output_blocks[block_pos][row][col];
        }

        // Decrypt
        if (mode == AES128)
            AES_decrypt(AES128, state_output_blocks[block_pos], expanded_key);
        else if (mode == AES192)
            AES_decrypt(AES192, state_output_blocks[block_pos], expanded_key);
        else 
            AES_decrypt(AES256, state_output_blocks[block_pos], expanded_key);

        // XOR IV with decrypted text
        for (col = 0; col < 4; col++)
        {
            for (row = 0; row < 4; row++)
                state_output_blocks[block_pos][row][col] ^= IV[row + (col * 4)];
        }

        // Update IV with previous cipher text values
        for (chain_pos = 0; chain_pos < 16; chain_pos++)
            IV[chain_pos] = chain[chain_pos];
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
    
    int i;
    int row, col;
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
    
    int i;
    int row, col;
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

//void word_rotate_192(int word[6], bool inverse)
//{
//    if (inverse)
//    {   // Shift last item to front
//        int temp = word[0];
//        word[0] = word[5];
//        word[5] = word[4];
//        word[4] = word[3];
//        word[3] = word[2];
//        word[2] = word[1];
//        word[1] = temp;
//    } else
//    {   // Shift first item to back
//        int temp = word[5];
//        word[5] = word[0];
//        word[0] = word[1];
//        word[1] = word[2];
//        word[2] = word[3];
//        word[3] = word[4];
//        word[4] = temp;
//    }
//}
//
//void key_scheduler_192(int temp[6], int rcon)
// {
//    int byte_pos;
//    word_rotate_192(temp, 0);
//    for (byte_pos = 0; byte_pos < 6; byte_pos++)
//    {
//        temp[byte_pos] = s_box_transform(temp[byte_pos], 0);
//        //printf("%02X", temp[byte_pos]);
//        //printf(" ");
//    }
//    //printf("\n");
//    temp[0] = temp[0]^rcon;
//}
//
//void word_rotate_256(int word[6], bool inverse)
//{
//    if (inverse)
//    {   // Shift last item to front
//        int temp = word[0];
//        word[0] = word[7];
//        word[7] = word[6];
//        word[6] = word[5];
//        word[5] = word[4];
//        word[4] = word[3];
//        word[3] = word[2];
//        word[2] = word[1];
//        word[1] = temp;
//    } else
//    {   // Shift first item to back
//        int temp = word[7];
//        word[7] = word[0];
//        word[0] = word[1];
//        word[1] = word[2];
//        word[2] = word[3];
//        word[3] = word[4];
//        word[4] = word[3];
//        word[5] = word[4];
//        word[6] = temp;
//    }
//}
//
//void key_scheduler_256(int temp[8], int rcon)
//{
//    int byte_pos;
//    word_rotate_256(temp, 0);
//    for (byte_pos = 0; byte_pos < 8; byte_pos++)
//    {
//        temp[byte_pos] = s_box_transform(temp[byte_pos], 0);
//        //printf("%02X", temp[byte_pos]);
//        //printf(" ");
//    }
//    //printf("\n");
//    temp[0] ^= rcon;
//}
