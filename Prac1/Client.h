#ifndef EHN_PRAC1_CLIENT_H
#define EHN_PRAC1_CLIENT_H


#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <unistd.h>
#include <string.h>


#define MAX_REQ_LEN 255


int main(int argc, char * argv[]);


void clear_buffer(char * buffer, int length);


#endif //EHN_PRAC1_CLIENT_H
