//
// Created by ivan on 2020/02/18.
//

#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

int main(){
    BIO *sbio, *out;
    int len;
    char tmpbuf[1024];
    SSL_CTX *ctx;
    SSL *ssl;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();

/* We would seed the PRNG here if the platform didn't
 * do it automatically
 */

    ctx = SSL_CTX_new(SSLv23_client_method());

/* We'd normally set some stuff like the verify paths and
 * mode here because as things stand this will connect to
 * any server whose certificate is signed by any CA.
 */

    sbio = BIO_new_ssl_connect(ctx);

    BIO_get_ssl(sbio, &ssl);

    if(!ssl) {
        fprintf(stderr, "Can't locate SSL pointer\n");
        /* whatever ... */
    }

/* Don't want any retries */
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

/* We might want to do other things with ssl here */

    BIO_set_conn_hostname(sbio, "0.0.0.0:4433");

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if(BIO_do_connect(sbio) <= 0) {
        printf("Error connecting to server\n");
    }

    if(BIO_do_handshake(sbio) <= 0) {
        printf("Error establishing SSL connection\n");
    }

/* Could examine ssl here to get connection info */

    BIO_puts(sbio, "GET / HTTP/1.0\n\n");
    for(;;) {
        len = BIO_read(sbio, tmpbuf, 1024);
        if(len <= 0) break;
        BIO_write(out, tmpbuf, len);
    }
    BIO_free_all(sbio);
    BIO_free(out);
}


