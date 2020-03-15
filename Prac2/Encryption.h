//
// Created by ivan on 2020/03/15.
//

#ifndef EHN_PRAC1_ENCRYPTION_H
#define EHN_PRAC1_ENCRYPTION_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


/// The maximum length of message to encrypt.
#define MAX_REQ_LEN 256


/// Add zeros if the block isn't the right length
char *pad_bits(char *block, int desired_length);

/// Convert char to block of hex
//void blockify(char *in_message, char ***state_output, int size);
void blockify16(char *in_message, char state_output[4][4][2], int size);
#endif //EHN_PRAC1_ENCRYPTION_H
