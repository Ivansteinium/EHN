//
// Created by ivan on 2020/03/15.
//

#include "Encryption.h"


int main(int argc, char *argv[])
{
    int state_size = 4;
    int message_len = -1;
    int num_blocks = -1;
    int current_block = 0;
    char state_array[MAX_REQ_LEN/(state_size*state_size)][state_size][state_size][2]; //[row][col][hex_byte]
    char message[MAX_REQ_LEN] = "test functionality";



    // Greeting
    printf("EHN 410 Group 12 Practical 2\n\n");
    // To be encrypted
    fgets(message, MAX_REQ_LEN, stdin);
    message_len = strlen(message);
//    blockify16(message, state_array[0], state_size);

    num_blocks = message_len/16;

    for (current_block = 0; current_block < num_blocks; ++current_block) {
        blockify16(message, state_array[current_block], 0);
    }

    if(message_len%16 != 0){
        blockify16(message, state_array[0], 0);

//        int byte_pos = 0;
//        int row, col;
//        for (col = 0; col < state_size; col++) {
//            for (row = 0; row < state_size; row++) {
//                sprintf((char*)(state_array[0][row][col]),"%02X", message[byte_pos]);
//                byte_pos++;
//            }
//        }
    }





}


char *pad_bits(char *block, int desired_length){
    int block_len = strlen(block);

}



void blockify16(char *in_message, char state_output[4][4][2], int start_pos){
    int byte_pos = start_pos;
    int row, col;
    for (col = 0; col < 4; col++) {
        for (row = 0; row < 4; row++) {
            sprintf((char*)(state_output[row][col]),"%02X", in_message[byte_pos]);
            byte_pos++;
        }
    }
}