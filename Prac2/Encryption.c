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

    word_rotate_32(test);

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
    word[3] = word[2];
    word[2] = word[1];
    word[1] = word[0];
    word[0] = temp;
}