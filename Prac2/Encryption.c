//
// Created by ivan on 2020/03/15.
//

#include "Encryption.h"


int main(int argc, char *argv[])
{
    int state_size = 4;
    int message_len = -1;
    int num_blocks = -1;
    int padding_pos = -1;
    int current_block = 0;
    int message_pos = 0;
    char state_array[MAX_REQ_LEN/(state_size*state_size)][state_size][state_size][3]; //[row][col][hex_byte]
    char message[MAX_REQ_LEN] = "test functionality";
    char test[4][3] = {"3A", "65", "71", "1B"};

    word_rotate_32(test);

    // Greeting
    printf("EHN 410 Group 12 Practical 2\n\n");
    // To be encrypted
    //fgets(message, MAX_REQ_LEN, stdin);
    message_len = strlen(message);
//    blockify16(message, state_array[0], state_size);

    num_blocks = message_len/16;
    if (message_len%16 != 0){
        num_blocks++;
    }



    for (current_block = 0; current_block < num_blocks; ++current_block) {
        blockify_16(message, state_array[current_block], message_pos);
        message_pos += 16;
        print_block_16(state_array[current_block]);
    }

//    if(message_len%16 != 0){
//
////        for (padding_pos = message_len; padding_pos < 16*(num_blocks+1); ++padding_pos) {
////            message[padding_pos] = '';
////        }
//        message[16*(num_blocks+1)] = '\0';
//
//        blockify16(message, state_array[0], 0);
//
////        int byte_pos = 0;
////        int row, col;
////        for (col = 0; col < state_size; col++) {
////            for (row = 0; row < state_size; row++) {
////                sprintf((char*)(state_array[0][row][col]),"%02X", message[byte_pos]);
////                byte_pos++;
////            }
////        }
//    }





}


char *pad_bits(char *block, int desired_length){
    int block_len = strlen(block);

}



void blockify_16(char *in_message, char state_output[4][4][3], int start_pos){
    int byte_pos = start_pos;
    int row, col;
    for (col = 0; col < 4; ++col) {
        for (row = 0; row < 4; ++row) {
            sprintf((char*)(state_output[row][col]),"%02X", in_message[byte_pos]);
            byte_pos++;
        }
    }
}

void print_block_16(char state_output[4][4][3]){
    int row, col;
    for (row = 0; row < 4; ++row) {
        for (col = 0; col < 4; ++col) {
           printf(state_output[row][col]);
           printf(" ");
        }
        printf("\n");
    }
    printf("\n");
}

void word_rotate_32(char word[4][3]){
    char temp[3];
    strcpy(temp, word[3]);
    strcpy(word[3], word[0]);
    strcpy(word[0], word[1]);
    strcpy(word[1], word[2]);
    strcpy(word[2], temp);
}