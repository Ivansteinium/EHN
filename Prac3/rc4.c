#include "rc4.h"


int main(int argc, char *argv[]) {
    struct rc4ctx_t RC4;
    U8 rc_key[] = "abcdefghijklmnop";

    rc4_init(&RC4, rc_key, 16);
    U8 out = rc4_getbyte(&RC4);
    return 0;
}


void swap(int* S, int idx_1, int idx_2){
    int temp = S[idx_1];
    S[idx_1] = S[idx_2];
    S[idx_2] = temp;
}


void rc4_init(struct rc4ctx_t* rc4c, U8* key, int keylen){
    int l;

//    rc4c->keylen = keylen;
    // Change key to int
    for (int i = 0; i < keylen; ++i) {
        rc4c->K[i] = (int)key[i];
    }

    // Set S and T
    for (int j = 0; j < 256; ++j){
        rc4c->S[j] = j;
        rc4c->T[j] = rc4c->K[j % keylen];
    }

    // Initial Permutation of S
    l = 0;
    for (int k = 0; k < 256; ++k) {
        l = (l + rc4c->S[k] + rc4c->T[k]) % 256;
        swap(rc4c->S, k, l);
    }

    // Set stream index
    rc4c->idx_1 = 0;
    rc4c->idx_2 = 0;
}

U8 rc4_getbyte(struct rc4ctx_t* rc4c){
    U8 stream_byte;
    int temp;

    rc4c->idx_1 = (rc4c->idx_1 + 1) % 256;
    rc4c->idx_2 = (rc4c->idx_2 + rc4c->S[rc4c->idx_1]) % 256;
    swap(rc4c->S, rc4c->idx_1, rc4c->idx_2);
    temp = (rc4c->S[rc4c->idx_1] + rc4c->S[rc4c->idx_2]) % 256;
    stream_byte = (unsigned char)temp;
    return stream_byte;
}

// Body

