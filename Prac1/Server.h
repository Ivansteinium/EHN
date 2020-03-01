#ifndef EHN_PRAC1_SERVER_H
#define EHN_PRAC1_SERVER_H


#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>


#define maxMediaItems  100
#define maxMediaNameSize  256


char MediaItems[maxMediaItems][maxMediaNameSize];
int numMediaItems = 0;


struct pthread_args
{   // This struct is passed as an argument to newly created threads
    // to allow multiple arguments to be passed
    BIO *abio; // The SSL object pointer
    int thread_number; // The current thread number
};


void *new_client_connection(void *ptr);


pthread_t *double_size(pthread_t *old_clients, int current_size);


int write_page(BIO *bio, const char *page, const char *filename);


int read_media();


int connect(BIO *bio);


char *itoa(char *dest, int i);


#endif //EHN_PRAC1_SERVER_H