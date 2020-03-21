//
// Created by ivan on 2020/03/15.
//

#include "Encryption.h"


int main(int argc, char *argv[])
{
    int i;
    int state_size = 4;
    int message_len = -1;
    int num_blocks = -1;
    int padding_pos = -1;
    int current_block = 0;
    int message_pos = 0;
    int state_array[MAX_REQ_LEN /
                    (state_size * state_size)][state_size][state_size];
    char message[MAX_REQ_LEN];
    int test[4] = {0x3A, 0x65, 0x71, 0x1B};
    int key[16] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x64, 0x6E, 0x61, 0x6C, 0x69};
    int key_24[24] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74,0x69, 0x64,
                      0x6E, 0x61, 0x6C, 0x69, 0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E};
    int key_36[36] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74,0x69, 0x64,
                      0x6E, 0x61, 0x6C, 0x69, 0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E,
                      0x6E, 0x61, 0x6C, 0x69, 0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E};
    int aes256_key[240];
    int aes192_key[208];
    int key_example[16] = {0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0x00, 0xaf, 0x7f, 0x67, 0x98};
    int aes_key[176];

    int test_cols[4][4] = {
            {0x74, 0x20, 0x61, 0x73},
            {0x68, 0x69, 0x20, 0x74},
            {0x69, 0x73, 0x74, 0x2e},
            {0x73, 0x20, 0x65, 0x2e}
    };

    aes_mix_cols(test_cols,0);
    aes_mix_cols(test_cols,1);


    key_expansion(aes_key, key);
    key_expansion_192(aes192_key, key_24);
    key_expansion_256(aes256_key, key_36);


    word_rotate_32(test, 0);
    word_rotate_32(test, 1);

    int a = s_box_transform(0x3a, 0);
    a = s_box_transform(a, 1);


    // Greeting
    printf("EHN 410 Group 12 Practical 2\n\n");
    // To be encrypted
    for(i = 0; i < MAX_REQ_LEN; i++)
        message[i] = '\0';
    strcpy(message, "test functionality");
    //fgets(message, MAX_REQ_LEN, stdin);
    message_len = strlen(message);

    num_blocks = message_len / 16;
    if(message_len % 16 != 0)
        num_blocks++;

    for(current_block = 0; current_block < num_blocks; current_block++)
    {
        blockify_16(message, state_array[current_block], message_pos);
        message_pos += 16;
        print_block_16(state_array[current_block]);
    }

    aes_256(state_array[0], aes256_key);
    decrypt_aes_256(state_array[0], aes256_key);
    print_block_16(state_array);

/*    if(message_len%16 != 0){

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

void blockify_16(char *in_message, int state_output[4][4], int start_pos)
{
    int byte_pos = start_pos;
    int row, col;
    for(col = 0; col < 4; col++)
    {
        for(row = 0; row < 4; row++)
        {
            state_output[row][col] = in_message[byte_pos];
            byte_pos++;
        }
    }
}

void hex_blockify_16(int in_message[16], int state_output[4][4]){
    int row, col;
    for(col = 0; col < 4; col++)
    {
        for(row = 0; row < 4; row++)
        {
            state_output[row][col] = in_message[(4*col)+row];
        }
    }
}

void print_block_16(int state_output[4][4])
{
    int row, col;
    for(row = 0; row < 4; row++)
    {
        for(col = 0; col < 4; col++)
        {
            printf("%02X", state_output[row][col]);
            printf(" ");
        }
        printf("\n");
    }
    printf("\n");
}


void word_rotate_32(int word[4], int inv)
{
    if(inv){
        // Shift last item to front
        int temp = word[0];
        word[0] = word[3];
        word[3] = word[2];
        word[2] = word[1];
        word[1] = temp;
    }
    else{
        // Shift first item to back
        int temp = word[3];
        word[3] = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = temp;
    }
}

int s_box_transform(int input, int inv){
    int MSB = input >> 4;
    int LSB = input & 0b00001111;
    MSB = MSB*2;
    if (LSB > 0x7){
        MSB++;
        LSB = LSB - 8;
    }

    if (inv){
        return s_inv[MSB][LSB];
    }
    return s_box[MSB][LSB];
}

int r_xpon_2(int prev){
    if(prev == 0x80){
        return 0x1B;
    }
    else if(prev*2 >= 0xFF){
        return 0xFF;
    } else{
        return prev*2;
    }
}

void key_scheduler(int temp[4], int rcon){
    int byte_pos;
    word_rotate_32(temp, 0);
    for (byte_pos = 0; byte_pos < 4; byte_pos++) {
        temp[byte_pos] = s_box_transform(temp[byte_pos], 0);
        //printf("%02X", temp[byte_pos]);
        //printf(" ");
    }
    //printf("\n");
    temp[0] = temp[0]^rcon;
}

void key_expansion(int aes_key_176[176], int user_key_16[16]){
    int key_pos;
    int sub_pos;
    int byte_pos;
    int expanded_pos;
    int temp[4];
    int rcon;
    int prev_rcon = 1;

    //Set first 16 bytes user key
    for (key_pos = 0; key_pos < 16; key_pos++) {
        aes_key_176[key_pos] = user_key_16[key_pos];
        if (key_pos > 11){
            temp[key_pos-12] = user_key_16[key_pos]; //Bits 12-15 into temp
        }
    }

//    key_scheduler(temp, rcon);
//    rcon++;
//
//    for (byte_pos = 0; byte_pos < 4; byte_pos++) {
//        temp[byte_pos] = temp[byte_pos] ^ aes_key_176[byte_pos]; //Bitwise XOR with 16bytes before
//        aes_key_176[byte_pos+16] = temp[byte_pos];               //Expand key
//    }

    // Repeat until 176Bytes
    for (expanded_pos = 0; expanded_pos < 10; expanded_pos++) {
        rcon = r_xpon_2(prev_rcon);
        key_scheduler(temp, prev_rcon);
        prev_rcon = rcon;

        for (byte_pos = 0; byte_pos < 4; byte_pos++) {
            temp[byte_pos] = temp[byte_pos] ^ aes_key_176[byte_pos+(16*expanded_pos)]; //Bitwise XOR with 16bytes before
            aes_key_176[byte_pos+16+(16*expanded_pos)] = temp[byte_pos];               //Expand key
        }

        for (sub_pos = 0; sub_pos < 3; sub_pos++) {
            for (byte_pos = 0; byte_pos < 4; byte_pos++) {
                temp[byte_pos] = temp[byte_pos] ^ aes_key_176[byte_pos+4+(16*expanded_pos)+(4*sub_pos)]; //Bitwise XOR with 16bytes before
                aes_key_176[byte_pos+4+16+(16*expanded_pos)+(4*sub_pos)] = temp[byte_pos];               //Expand key
            }
        }
    }


}


void aes_shift_rows(int state_output[4][4], int inv){
    int row;
    int num_rotations;
    for (row = 1; row < 4; row++) {
        for (num_rotations = 0; num_rotations < row; num_rotations++) {
            word_rotate_32(state_output[row], inv);
        }
    }

}


int matrix_dot(int prime_val, int col_val){
    int flag = 0;
    if (prime_val == 0x03){
        int left, right;
        left = matrix_dot(0x02, col_val);
        right = matrix_dot(0x01, col_val);
        return left^right;
    }
    else if (prime_val == 0x02){
        if ((col_val & 0b10000000) == 0b10000000){
            flag = 1;
        }
        col_val = (col_val << 1) & 0b011111111;
        if (flag){
            return col_val ^ 0b00011011;
        }
        return col_val;

    }
    else if(prime_val == 9){
        return matrix_dot(0x02, matrix_dot(0x02, matrix_dot(0x02, col_val))) ^ col_val;
    }
    else if(prime_val == 11){
        return matrix_dot(0x02, matrix_dot(0x02, matrix_dot(0x02, col_val)) ^ col_val) ^ col_val;
    }
    else if(prime_val == 13){
        return matrix_dot(0x02, matrix_dot(0x02, matrix_dot(0x02, col_val) ^ col_val)) ^ col_val;
    }
    else if(prime_val == 14){
        return matrix_dot(0x02, matrix_dot(0x02, matrix_dot(0x02, col_val) ^ col_val) ^ col_val);
    }
    else{
        return col_val;
    }
}


void aes_mix_cols(int state_output[4][4], int inv){
    int row, col, out;
    int new_state[4][4];
    int multiply[4];
    for (out = 0; out < 4; ++out) {
        for (row = 0; row < 4; row++) {
            for (col = 0; col < 4; col++) {
                if (inv){
                    multiply[col] = matrix_dot(inv_prime_matrix[row][col], state_output[col][out]);
                }
                else {
                    multiply[col] = matrix_dot(prime_matrix[row][col], state_output[col][out]);
                }
            }
            new_state[row][out] = multiply[0] ^ multiply[1] ^ multiply[2] ^ multiply[3];
        }
    }


    for (row = 0; row < 4; row++) {
        for (col = 0; col < 4; col++) {
            state_output[row][col] = new_state[row][col];
        }
    }
}


void aes_128(int state_output[4][4], int key[176]){
    int row, col;
    int round;
    int key_index = 0;
    // Initial round
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
        }
    }
    // Update key position
    key_index = key_index + 16;

    // Encryption Rounds Nr - 1
    for (round = 0; round < 9; round++) {

        // Sub bytes
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output[row][col] = s_box_transform(state_output[row][col], 0);
            }
        }

        // Shift rows
        aes_shift_rows(state_output, 0);

        // Mix columns
        aes_mix_cols(state_output, 0);

        // Add round key
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
            }
        }
        // Update key position
        key_index = key_index + 16;
    }

    // Final round
    // Sub bytes
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = s_box_transform(state_output[row][col], 0);
        }
    }

    // Shift rows
    aes_shift_rows(state_output, 0);

    // Add round key
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
        }
    }
}


void decrypt_aes_128(int state_output[4][4], int key[176]){
    int row, col;
    int round;
    int key_index = 160;
    // Initial round
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
        }
    }
    // Update key position
    key_index = key_index - 16;

    // Encryption Rounds Nr - 1
    for (round = 0; round < 9; round++) {

        // Inverse sub bytes
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output[row][col] = s_box_transform(state_output[row][col], 1);
            }
        }

        // Inverse shift rows
        aes_shift_rows(state_output, 1);

        // Inverse mix columns
        aes_mix_cols(state_output, 1);

        // Add round key
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
            }
        }
        // Update key position
        key_index = key_index - 16;
    }

    // Final round
    // Inverse sub bytes
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = s_box_transform(state_output[row][col], 1);
        }
    }

    // Inverse shift rows
    aes_shift_rows(state_output, 1);

    // Add round key
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
        }
    }
}







void cbc_encrypt(int state_output_blocks[][4][4], int num_blocks, int IV[16], int key[176], int encryption){
    int row, col;
    int block_pos;
    for (block_pos = 0; block_pos < num_blocks; block_pos++) {
        // XOR chain with plaintext
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output_blocks[block_pos][row][col] = state_output_blocks[block_pos][row][col] ^ IV[row+(col*4)];
            }
        }

        // Encrypt
        if(encryption == 0){
            aes_128(state_output_blocks[block_pos], key);
        }
        else if(encryption == 1){
            aes_192(state_output_blocks[block_pos], key);
        }
        else{
            aes_256(state_output_blocks[block_pos], key);
        }



        // Update chain with cipher text values
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                IV[row+(col*4)] = state_output_blocks[block_pos][row][col];
            }
        }
    }
}


void cbc_decrypt(int state_output_blocks[][4][4], int num_blocks, int IV[16], int key[176], int encryption){
    int row, col;
    int block_pos, chain_pos;
    int chain[16];
    for (block_pos = 0; block_pos < num_blocks; block_pos++) {
        // Update chain with cipher text values
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                chain[row+(col*4)] = state_output_blocks[block_pos][row][col];
            }
        }


        // Decrypt
        if(encryption == 0){
            decrypt_aes_128(state_output_blocks[block_pos], key);
        }
        else if(encryption == 1){
            decrypt_aes_192(state_output_blocks[block_pos], key);
        }
        else{
            decrypt_aes_256(state_output_blocks[block_pos], key);
        }



        // XOR IV with decrypted text
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output_blocks[block_pos][row][col] = state_output_blocks[block_pos][row][col] ^ IV[row+(col*4)];
            }
        }

        // Update IV with previous cipher text values
        for (chain_pos = 0; chain_pos < 16; chain_pos++) {
            IV[chain_pos] = chain[chain_pos];
        }
    }
}

void shift_bytes(int input[16]){
    int i;
    for (i = 0; i < 8; i++) {
        input[i] = input[i+8];
    }
}

void cfb_encrypt(int stream_input[][8], int num_blocks, int IV[16], int key[176], int encryption){
    int row, col;
    int block_pos;
    int block[4][4];

    for (block_pos = 0; block_pos < num_blocks; block_pos++) {
        hex_blockify_16(IV, block);

        // Encrypt
        if(encryption == 0){
            aes_128(block, key);
        }
        else if(encryption == 1){
            aes_192(block, key);
        }
        else{
            aes_256(block, key);
        }

        // Move bytes
        shift_bytes(IV);

        // XOR chain with plaintext
        for (col = 0; col < 2; col++) {
            for (row = 0; row < 4; row++) {
                stream_input[block_pos][row + (col*4)] = block[row][col] ^ stream_input[block_pos][row + (col*4)];
                IV[row + (col*4) + 8] = stream_input[block_pos][row + (col*4)];
            }
        }
    }
}

void cfb_decrypt(int stream_input[][8], int num_blocks, int IV[16], int key[176], int encryption){
    int row, col;
    int block_pos;
    int block[4][4];

    for (block_pos = 0; block_pos < num_blocks; block_pos++) {
        hex_blockify_16(IV, block);

        // Decrypt
        if(encryption == 0){
            decrypt_aes_128(block, key);
        }
        else if(encryption == 1){
            decrypt_aes_192(block, key);
        }
        else{
            decrypt_aes_256(block, key);
        }

        // Move bytes
        shift_bytes(IV);

        // XOR chain with plaintext
        for (col = 0; col < 2; col++) {
            for (row = 0; row < 4; row++) {
                IV[row + (col*4) + 8] = stream_input[block_pos][row + (col*4)];
                stream_input[block_pos][row + (col*4)] = block[row][col] ^ stream_input[block_pos][row + (col*4)];
            }
        }
    }
}

//void word_rotate_192(int word[6], int inv)
//{
//    if(inv){
//        // Shift last item to front
//        int temp = word[0];
//        word[0] = word[5];
//        word[5] = word[4];
//        word[4] = word[3];
//        word[3] = word[2];
//        word[2] = word[1];
//        word[1] = temp;
//    }
//    else{
//        // Shift first item to back
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
//void key_scheduler_192(int temp[6], int rcon){
//    int byte_pos;
//    word_rotate_192(temp, 0);
//    for (byte_pos = 0; byte_pos < 6; byte_pos++) {
//        temp[byte_pos] = s_box_transform(temp[byte_pos], 0);
//        //printf("%02X", temp[byte_pos]);
//        //printf(" ");
//    }
//    //printf("\n");
//    temp[0] = temp[0]^rcon;
//}


void key_expansion_192(int aes_key_208[208], int user_key_24[24]){
    int key_pos;
    int sub_pos;
    int byte_pos;
    int expanded_pos;
    int temp[4];
    int temp_key[216];
    int set_pos;
    int rcon;
    int prev_rcon = 1;

    //Set first 24 bytes user key
    for (key_pos = 0; key_pos < 24; key_pos++) {
        temp_key[key_pos] = user_key_24[key_pos];
        if (key_pos > 19){
            temp[key_pos-20] = user_key_24[key_pos]; //Bits 20-23 into temp
        }
    }

//    key_scheduler(temp, rcon);
//    rcon++;
//
//    for (byte_pos = 0; byte_pos < 4; byte_pos++) {
//        temp[byte_pos] = temp[byte_pos] ^ aes_key_176[byte_pos]; //Bitwise XOR with 16bytes before
//        aes_key_176[byte_pos+16] = temp[byte_pos];               //Expand key
//    }


    for (expanded_pos = 0; expanded_pos < 8; expanded_pos++) {
        rcon = r_xpon_2(prev_rcon);
        key_scheduler(temp, prev_rcon);
        prev_rcon = rcon;


        for (byte_pos = 0; byte_pos < 4; byte_pos++) {
            temp[byte_pos] = temp[byte_pos] ^ temp_key[byte_pos+(24*expanded_pos)]; //Bitwise XOR with 24bytes before
            temp_key[byte_pos+24+(24*expanded_pos)] = temp[byte_pos];               //Expand key
        }

        for (sub_pos = 0; sub_pos < 5; sub_pos++) {
            for (byte_pos = 0; byte_pos < 4; byte_pos++) {
                temp[byte_pos] = temp[byte_pos] ^ temp_key[byte_pos+4+(24*expanded_pos)+(4*sub_pos)]; //Bitwise XOR with 16bytes before
                temp_key[byte_pos+4+24+(24*expanded_pos)+(4*sub_pos)] = temp[byte_pos];               //Expand key
            }
        }
    }

    for (set_pos = 0; set_pos < 208; set_pos++) {
        aes_key_208[set_pos] = temp_key[set_pos];
    }
}


//void word_rotate_256(int word[6], int inv)
//{
//    if(inv){
//        // Shift last item to front
//        int temp = word[0];
//        word[0] = word[7];
//        word[7] = word[6];
//        word[6] = word[5];
//        word[5] = word[4];
//        word[4] = word[3];
//        word[3] = word[2];
//        word[2] = word[1];
//        word[1] = temp;
//    }
//    else{
//        // Shift first item to back
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
//void key_scheduler_256(int temp[8], int rcon){
//    int byte_pos;
//    word_rotate_256(temp, 0);
//    for (byte_pos = 0; byte_pos < 8; byte_pos++) {
//        temp[byte_pos] = s_box_transform(temp[byte_pos], 0);
//        //printf("%02X", temp[byte_pos]);
//        //printf(" ");
//    }
//    //printf("\n");
//    temp[0] = temp[0]^rcon;
//}

void key_expansion_256(int aes_key_240[240], int user_key_32[32]){
    int key_pos;
    int sub_pos;
    int byte_pos;
    int expanded_pos;
    int temp[4];
    int temp_key[256] = {};
    int set_pos;
    int rcon;
    int prev_rcon = 1;

    //Set first 32 bytes user key
    for (key_pos = 0; key_pos < 32; key_pos++) {
        temp_key[key_pos] = user_key_32[key_pos];
        if (key_pos > 27){
            temp[key_pos-28] = user_key_32[key_pos]; //Bits 28-31 into temp
        }
    }

//    key_scheduler(temp, rcon);
//    rcon++;
//
//    for (byte_pos = 0; byte_pos < 4; byte_pos++) {
//        temp[byte_pos] = temp[byte_pos] ^ aes_key_176[byte_pos]; //Bitwise XOR with 16bytes before
//        aes_key_176[byte_pos+16] = temp[byte_pos];               //Expand key
//    }


    for (expanded_pos = 0; expanded_pos < 7; expanded_pos++) {
        rcon = r_xpon_2(prev_rcon);
        key_scheduler(temp, prev_rcon);
        prev_rcon = rcon;

        printf("before\n");
        for (byte_pos = 0; byte_pos < 4; byte_pos++) {
            temp[byte_pos] = temp[byte_pos] ^ temp_key[byte_pos+(32*expanded_pos)]; //Bitwise XOR with 24bytes before
            temp_key[byte_pos+32+(32*expanded_pos)] = temp[byte_pos];               //Expand key
        }

        for (sub_pos = 0; sub_pos < 7; sub_pos++) {
            for (byte_pos = 0; byte_pos < 4; byte_pos++) {
                temp[byte_pos] = temp[byte_pos] ^ temp_key[byte_pos+4+(32*expanded_pos)+(4*sub_pos)]; //Bitwise XOR with 16bytes before
                temp_key[byte_pos+4+32+(32*expanded_pos)+(4*sub_pos)] = temp[byte_pos];               //Expand key
            }
        }
    }

    for (set_pos = 0; set_pos < 240; set_pos++) {
        aes_key_240[set_pos] = temp_key[set_pos];
    }
}


void aes_192(int state_output[4][4], int key[208]){
    int row, col;
    int round;
    int key_index = 0;
    // Initial round
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
        }
    }
    // Update key position
    key_index = key_index + 16;

    // Encryption Rounds Nr - 1
    for (round = 0; round < 11; round++) {

        // Sub bytes
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output[row][col] = s_box_transform(state_output[row][col], 0);
            }
        }

        // Shift rows
        aes_shift_rows(state_output, 0);

        // Mix columns
        aes_mix_cols(state_output, 0);

        // Add round key
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
            }
        }
        // Update key position
        key_index = key_index + 16;
    }

    // Final round
    // Sub bytes
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = s_box_transform(state_output[row][col], 0);
        }
    }

    // Shift rows
    aes_shift_rows(state_output, 0);

    // Add round key
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
        }
    }
}


void decrypt_aes_192(int state_output[4][4], int key[208]){
    int row, col;
    int round;
    int key_index = 160;
    // Initial round
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
        }
    }
    // Update key position
    key_index = key_index - 16;

    // Encryption Rounds Nr - 1
    for (round = 0; round < 11; round++) {

        // Inverse sub bytes
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output[row][col] = s_box_transform(state_output[row][col], 1);
            }
        }

        // Inverse shift rows
        aes_shift_rows(state_output, 1);

        // Inverse mix columns
        aes_mix_cols(state_output, 1);

        // Add round key
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
            }
        }
        // Update key position
        key_index = key_index - 16;
    }

    // Final round
    // Inverse sub bytes
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = s_box_transform(state_output[row][col], 1);
        }
    }

    // Inverse shift rows
    aes_shift_rows(state_output, 1);

    // Add round key
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
        }
    }
}


void aes_256(int state_output[4][4], int key[240]){
    int row, col;
    int round;
    int key_index = 0;
    // Initial round
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
        }
    }
    // Update key position
    key_index = key_index + 16;

    // Encryption Rounds Nr - 1
    for (round = 0; round < 11; round++) {

        // Sub bytes
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output[row][col] = s_box_transform(state_output[row][col], 0);
            }
        }

        // Shift rows
        aes_shift_rows(state_output, 0);

        // Mix columns
        aes_mix_cols(state_output, 0);

        // Add round key
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
            }
        }
        // Update key position
        key_index = key_index + 16;
    }

    // Final round
    // Sub bytes
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = s_box_transform(state_output[row][col], 0);
        }
    }

    // Shift rows
    aes_shift_rows(state_output, 0);

    // Add round key
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
        }
    }
}


void decrypt_aes_256(int state_output[4][4], int key[240]){
    int row, col;
    int round;
    int key_index = 160;
    // Initial round
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
        }
    }
    // Update key position
    key_index = key_index - 16;

    // Encryption Rounds Nr - 1
    for (round = 0; round < 11; round++) {

        // Inverse sub bytes
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output[row][col] = s_box_transform(state_output[row][col], 1);
            }
        }

        // Inverse shift rows
        aes_shift_rows(state_output, 1);

        // Inverse mix columns
        aes_mix_cols(state_output, 1);

        // Add round key
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++) {
                state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
            }
        }
        // Update key position
        key_index = key_index - 16;
    }

    // Final round
    // Inverse sub bytes
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = s_box_transform(state_output[row][col], 1);
        }
    }

    // Inverse shift rows
    aes_shift_rows(state_output, 1);

    // Add round key
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            state_output[row][col] = state_output[row][col] ^ key[row+(col*4) + key_index];
        }
    }
}