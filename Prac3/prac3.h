#ifndef EHN_PRAC3_H
#define EHN_PRAC3_H

// Common includes
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <ctype.h>

// Common defines


// Body
//Body
struct rc4info_t
{
    int S[255];
    int i,j;
};

void swap(int *a, int *b);
void rc4_init(struct rc4info_t *rc4i, unsigned char *key, int keylen);
unsigned char rc4_getbyte(struct rc4info_t *rc4i);




#endif //EHN_PRAC3_H

