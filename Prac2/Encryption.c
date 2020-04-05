#include "Encryption.h"


int main(int argc, char *argv[])
{
    int i;
    int message_len = -1;
    int num_blocks = -1;
//    int padding_pos = -1;
    int current_block = 0;
    int message_pos = 0;
    int state_array[MAX_REQ_LEN / 16][4][4];
    char message[MAX_REQ_LEN];

    int AES128_user_key[AES128_USER_KEY_SIZE] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x64,
                                                 0x6E, 0x61, 0x6C, 0x69};
    int AES192_user_key[AES192_USER_KEY_SIZE] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x64,
                                                 0x6E, 0x61, 0x6C, 0x69, 0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E};
    int AES256_user_key[AES256_USER_KEY_SIZE] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x64,
                                                 0x6E, 0x61, 0x6C, 0x69, 0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E,
                                                 0x6E, 0x61, 0x6C, 0x69, 0x74, 0x65, 0x73, 0x74};
    int AES128_key[AES128_KEY_SIZE];
    int AES192_key[AES192_KEY_SIZE];
    int AES256_key[AES256_KEY_SIZE];

    //    **** TESTING PURPOSES **** /*
    // TODO: remove when no longer needed
    int test[4] = {0x3A, 0x65, 0x71, 0x1B};
    int key_example[16] = {0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0x00,
                           0xaf, 0x7f, 0x67, 0x98};
    int test_cols[4][4] = {{0x74, 0x20, 0x61, 0x73},
                           {0x68, 0x69, 0x20, 0x74},
                           {0x69, 0x73, 0x74, 0x2e},
                           {0x73, 0x20, 0x65, 0x2e}};

    AES_mix_cols(test_cols, false);
    AES_mix_cols(test_cols, true);

    key_expansion(AES128, AES128_key, AES128_user_key);
    key_expansion(AES192, AES192_key, AES192_user_key);
    key_expansion(AES256, AES256_key, AES256_user_key);

    word_rotate_32(test, false);
    word_rotate_32(test, true);

    int a = s_box_transform(0x3a, false);
    a = s_box_transform(a, true);
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

    for (current_block = 0; current_block < num_blocks; current_block++)
    {
        char_blockify_16(message, state_array[current_block], message_pos);
        message_pos += 16;
        printf("Block %d\n", current_block);
        print_block_16(state_array[current_block]);
    }

    //    **** TESTING PURPOSES **** /*
    // TODO: fix
    printf("Before\n");
    print_block_16(state_array[0]);
    AES_encrypt(AES256, state_array[0], AES256_key);
    AES_decrypt(AES256, state_array[0], AES256_key);
    printf("After (should be same as before)\n");
    print_block_16(state_array[0]);
    // */ **** TESTING PURPOSES ****

/*    if (message_len%16 != 0){

//        for (padding_pos = message_len; padding_pos < 16*(num_blocks+1); ++padding_pos) {
//            message[padding_pos] = '';
//        }
        message[16*(num_blocks+1)] = '\0';

        blockify16(message, state_array[0], 0);

//        int byte_pos = 0;
//        int row, col;
//        for (col = 0; col < state_size; col++) {
//            for (row = 0; row < state_size; row++) {
//                sprintf((char*)(state_array[0][row][col]),"%02X", message[byte_pos]);
//                byte_pos++;
//            }
//        }
    }*/
}


// Convert char array to block of hex
void char_blockify_16(char *in_message, int state_output[4][4], int start_pos)
{
    int byte_pos = start_pos;
    int row, col;
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            state_output[row][col] = in_message[byte_pos++];
    }
}


// Convert integer array to block of hex
void hex_blockify_16(int in_message[16], int state_output[4][4])
{
    int row, col;
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            state_output[row][col] = in_message[(4 * col) + row];
    }
}


// Output blocks to terminal as 4 by 4 hex
void print_block_16(int state_output[4][4])
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


// Shift last item to front
void word_rotate_32(int word[4], bool inverse)
{
    int temp;
    if (inverse)
    {   // Shift last item to front
        temp = word[0];
        word[0] = word[3];
        word[3] = word[2];
        word[2] = word[1];
        word[1] = temp;
    } else
    {   // Shift first item to back
        temp = word[3];
        word[3] = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = temp;
    }
}


// Divide value up into MSB and LSB Nibble and return s_box value
int s_box_transform(int input, bool inverse)
{
    int MSB = (input >> 4) * 2;
    int LSB = input & 0b00001111;

    if (LSB > 0x7)
    {
        MSB++;
        LSB -= 8;
    }

    if (inverse)
        return s_inv[MSB][LSB];
    else
        return s_box[MSB][LSB];
}


// Exponentiation of 2, double previous except 0x80 and max value of 0xFF
int r_xpon_2(int previous)
{
    if (previous == 0x80)
        return 0x1B;
    else if (previous * 2 >= 0xFF)
        return 0xFF;
    else
        return previous * 2;
}


// Core key operation transform of previous 4 bytes
void key_scheduler(int temp[4], int rcon)
{
    int byte_pos;
    word_rotate_32(temp, 0);
    for (byte_pos = 0; byte_pos < 4; byte_pos++)
    {
        temp[byte_pos] = s_box_transform(temp[byte_pos], 0);
//        printf("%02X", temp[byte_pos]);
//        printf(" ");
    }
//    printf("\n");
    temp[0] ^= rcon;
}


// Main key expansion function
void key_expansion(int mode, int *AES_key, int *user_key)
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

    int sub_pos;
    int byte_pos;
    int temp[4];
    int rcon;
    int prev_rcon = 1;

    // Set first x bytes user key
    int key_pos;
    for (key_pos = 0; key_pos < user_key_size; key_pos++)
        AES_key[key_pos] = user_key[key_pos];

    // Last 4 bits into temp
    for (key_pos = 0; key_pos < 4; key_pos++)
        temp[key_pos] = user_key[user_key_size - (4 - key_pos) - 1];

//    key_scheduler(temp, rcon);
//    rcon++;
//
//    for (byte_pos = 0; byte_pos < 4; byte_pos++)
//    {
//        temp[byte_pos] ^= aes_key[byte_pos]; // Bitwise XOR with x bytes before
//        aes_key[byte_pos+16] = temp[byte_pos]; // Expand key
//    }

    int expanded_pos;
    for (expanded_pos = 0; expanded_pos < expansion; expanded_pos++)
    {
        rcon = r_xpon_2(prev_rcon);
        key_scheduler(temp, prev_rcon);
        prev_rcon = rcon;

        for (byte_pos = 0; byte_pos < 4; byte_pos++)
        {
            temp[byte_pos] ^= AES_key[byte_pos + (user_key_size * expanded_pos)]; // Bitwise XOR with x bytes before
            AES_key[byte_pos + user_key_size + (user_key_size * expanded_pos)] = temp[byte_pos]; // Expand key
        }

        for (sub_pos = 0; sub_pos < sub_expansion; sub_pos++)
        {
            for (byte_pos = 0; byte_pos < 4; byte_pos++)
            {
                temp[byte_pos] ^= AES_key[byte_pos + 4 + (user_key_size * expanded_pos) + (4 * sub_pos)]; // Bitwise XOR with x bytes before
                AES_key[byte_pos + 4 + user_key_size + (user_key_size * expanded_pos) + (4 * sub_pos)] = temp[byte_pos]; // Expand key
            }
        }
    }
}


// Shift rows the row index amount of times
void AES_shift_rows(int state_output[4][4], bool inverse)
{
    int row;
    int num_rotations;
    for (row = 1; row < 4; row++)
    {
        for (num_rotations = 0; num_rotations < row; num_rotations++)
            word_rotate_32(state_output[row], inverse);
    }
}


// Recursive multiplication of the column value and prime matrix
int matrix_dot(int prime_val, int col_val)
{
    int flag = 0;
    if (prime_val == 0x03)
    {
        int left = matrix_dot(0x02, col_val);
        int right = matrix_dot(0x01, col_val);
        return left ^ right;
    } else if (prime_val == 0x02)
    {
        if ((col_val & 0b10000000) == 0b10000000)
            flag = 1;
        col_val = (col_val << 1) & 0b011111111;
        if (flag)
            return col_val ^ 0b00011011;
        return col_val;
    } else if (prime_val == 9)
        return matrix_dot(0x02, matrix_dot(0x02, matrix_dot(0x02, col_val))) ^ col_val;
    else if (prime_val == 11)
        return matrix_dot(0x02, matrix_dot(0x02, matrix_dot(0x02, col_val)) ^ col_val) ^ col_val;
    else if (prime_val == 13)
        return matrix_dot(0x02, matrix_dot(0x02, matrix_dot(0x02, col_val) ^ col_val)) ^ col_val;
    else if (prime_val == 14)
        return matrix_dot(0x02, matrix_dot(0x02, matrix_dot(0x02, col_val) ^ col_val) ^ col_val);
    else
        return col_val;
}


// Easy matrix dot and XOR
void AES_mix_cols(int state_output[4][4], bool inverse)
{
    int row, col, out;
    int new_state[4][4];
    int multiply[4];
    for (out = 0; out < 4; ++out)
    {
        for (row = 0; row < 4; row++)
        {
            for (col = 0; col < 4; col++)
            {
                if (inverse)
                    multiply[col] = matrix_dot(inv_prime_matrix[row][col], state_output[col][out]);
                else
                    multiply[col] = matrix_dot(prime_matrix[row][col], state_output[col][out]);
            }
            new_state[row][out] = multiply[0] ^ multiply[1] ^ multiply[2] ^ multiply[3];
        }
    }

    for (row = 0; row < 4; row++)
    {
        for (col = 0; col < 4; col++)
            state_output[row][col] = new_state[row][col];
    }
}


void AES_round(int state_output[4][4], int *key, int key_index, bool mix_cols, bool inverse)
{
    // Substitute bytes
    int row, col;
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            state_output[row][col] = s_box_transform(state_output[row][col], inverse);
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
            state_output[row][col] ^= key[row + (col * 4) + key_index];
    }
}


// The AES encryption algorithm
void AES_encrypt(int mode, int state_output[4][4], int *key) // TODO: compare with known result
{
    int number_of_rounds;

    if (mode == AES128)
        number_of_rounds = AES128_ROUNDS;
    else if (mode == AES192)
        number_of_rounds = AES192_ROUNDS;
    else if (mode == AES256)
        number_of_rounds = AES256_ROUNDS;
    else
        return;

    int row, col;
    int key_index = 0;

    // Initial round, add round key
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            state_output[row][col] ^= key[row + (col * 4) + key_index];
    }

    // Perform the normal rounds
    int round;
    for (round = 0; round < number_of_rounds - 1; round++)
    {
        key_index += 16; // Update key position
        AES_round(state_output, key, key_index, true, false); // Perform a normal AES round
    }

    // Last round is a special case
    key_index += 16; // Update key position
    AES_round(state_output, key, key_index, false, false); // Perform a last AES round
}


// The AES decryption algorithm
void AES_decrypt(int mode, int state_output[4][4], int *key) // TODO: decrypt not yielding plaintext as expected
{
    int number_of_rounds;
    int key_index;

    if (mode == AES128)
    {
        number_of_rounds = AES128_ROUNDS;
        key_index = AES128_KEY_SIZE;
    } else if (mode == AES192)
    {
        number_of_rounds = AES192_ROUNDS;
        key_index = AES192_KEY_SIZE;
    } else if (mode == AES256)
    {
        number_of_rounds = AES256_ROUNDS;
        key_index = AES256_KEY_SIZE;
    } else
        return;

    int row, col;

    // First round is a special case
    key_index -= 16; // Update key position
    AES_round(state_output, key, key_index, false, true); // Perform a first AES round

    // Perform the normal rounds
    int round;
    for (round = 0; round < number_of_rounds - 1; round++)
    {
        key_index -= 16; // Update key position
        AES_round(state_output, key, key_index, true, true); // Perform a normal AES round
    }

    // Last round, add round key
    key_index -= 16; // Update key position
    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
            state_output[row][col] ^= key[row + (col * 4) + key_index];
    }
}


// The Cipher Block Chaining encryption
void CBC_encrypt(int mode, int state_output_blocks[][4][4], int num_blocks, int IV[16], int *key) // TODO: not tested
{
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
            AES_encrypt(AES128, state_output_blocks[block_pos], key);
        else if (mode == AES192)
            AES_encrypt(AES192, state_output_blocks[block_pos], key);
        else if (mode == AES256)
            AES_encrypt(AES256, state_output_blocks[block_pos], key);

        // Update chain with cipher text values
        for (col = 0; col < 4; col++)
        {
            for (row = 0; row < 4; row++)
                IV[row + (col * 4)] = state_output_blocks[block_pos][row][col];
        }
    }
}


// The Cipher Block Chaining decryption
void CBC_decrypt(int mode, int state_output_blocks[][4][4], int num_blocks, int IV[16], int *key) // TODO: not tested
{
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
            AES_decrypt(AES128, state_output_blocks[block_pos], key);
        else if (mode == AES192)
            AES_decrypt(AES192, state_output_blocks[block_pos], key);
        else if (mode == AES256)
            AES_decrypt(AES256, state_output_blocks[block_pos], key);

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
}


// Helper for shifting buffer contents in CFB
void shift_bytes(int input[16])
{
    int i;
    for (i = 0; i < 8; i++)
        input[i] = input[i + 8];
}


// The Cipher Feedback encryption
void CFB_encrypt(int mode, int stream_input[][8], int num_blocks, int IV[16], int *key) // TODO: not tested
{
    int row, col;
    int block[4][4];

    int block_pos;
    for (block_pos = 0; block_pos < num_blocks; block_pos++)
    {
        hex_blockify_16(IV, block);

        // Encrypt
        if (mode == AES128)
            AES_encrypt(AES128, block, key);
        else if (mode == AES192)
            AES_encrypt(AES192, block, key);
        else if (mode == AES256)
            AES_encrypt(AES256, block, key);

        // Move bytes
        shift_bytes(IV);

        // XOR chain with plaintext
        for (col = 0; col < 2; col++)
        {
            for (row = 0; row < 4; row++)
            {
                stream_input[block_pos][row + (col * 4)] ^= block[row][col];
                IV[row + (col * 4) + 8] = stream_input[block_pos][row + (col * 4)];
            }
        }
    }
}


// The Cipher Feedback decryption
void CFB_decrypt(int mode, int stream_input[][8], int num_blocks, int IV[16], int *key) // TODO: not tested
{
    int row, col;
    int block[4][4];

    int block_pos;
    for (block_pos = 0; block_pos < num_blocks; block_pos++)
    {
        hex_blockify_16(IV, block);

        // Decrypt
        if (mode == AES128)
            AES_decrypt(AES128, block, key);
        else if (mode == AES192)
            AES_decrypt(AES192, block, key);
        else if (mode == AES256)
            AES_decrypt(AES256, block, key);

        // Move bytes
        shift_bytes(IV);

        // XOR chain with plaintext
        for (col = 0; col < 2; col++)
        {
            for (row = 0; row < 4; row++)
            {
                IV[row + (col * 4) + 8] = stream_input[block_pos][row + (col * 4)];
                stream_input[block_pos][row + (col * 4)] ^= block[row][col];
            }
        }
    }
}

//void word_rotate_192(int word[6], bool inverse)
//{
//    int temp;
//    if (inverse)
//    {   // Shift last item to front
//        temp = word[0];
//        word[0] = word[5];
//        word[5] = word[4];
//        word[4] = word[3];
//        word[3] = word[2];
//        word[2] = word[1];
//        word[1] = temp;
//    } else
//    {   // Shift first item to back
//        temp = word[5];
//        word[5] = word[0];
//        word[0] = word[1];
//        word[1] = word[2];
//        word[2] = word[3];
//        word[3] = word[4];
//        word[4] = temp;
//    }
//}
//
//void key_scheduler_192(int temp[6], int rcon){
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
//    int temp;
//    if (inverse)
//    {   // Shift last item to front
//        temp = word[0];
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
//        temp = word[7];
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

