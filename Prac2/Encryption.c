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
    int test[4] = {0xEF, 0x65, 0x71, 0x1B};
    int key[16] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x64, 0x6E, 0x61, 0x6C, 0x69};
    int key_example[16] = {0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0x00, 0xaf, 0x7f, 0x67, 0x98};
    int aes_key[176];
    key_expansion(aes_key, key);

    //word_rotate_32(test);
    int a = s_box_transform(test[0]);

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


void word_rotate_32(int word[4])
{
    // Shift last item to front
    int temp = word[3];
    word[3] = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = temp;
}

int s_box_transform(int input){
    int MSB = input >> 4;
    int LSB = input & 0b00001111;
    MSB = MSB*2;
    if (LSB > 0x7){
        MSB++;
        LSB = LSB - 8;
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
    word_rotate_32(temp);
    for (byte_pos = 0; byte_pos < 4; byte_pos++) {
        temp[byte_pos] = s_box_transform(temp[byte_pos]);
        printf("%02X", temp[byte_pos]);
        printf(" ");
    }
    printf("\n");
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

        for (int sub_pos = 0; sub_pos < 3; sub_pos++) {
            for (byte_pos = 0; byte_pos < 4; byte_pos++) {
                temp[byte_pos] = temp[byte_pos] ^ aes_key_176[byte_pos+4+(16*expanded_pos)+(4*sub_pos)]; //Bitwise XOR with 16bytes before
                aes_key_176[byte_pos+4+16+(16*expanded_pos)+(4*sub_pos)] = temp[byte_pos];               //Expand key
            }
        }
    }


}