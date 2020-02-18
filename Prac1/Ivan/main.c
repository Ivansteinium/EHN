#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

void *print_message_function( void *ptr );
int write_page(BIO *bio, const char *page);
int connect(BIO *bio);

int main() {
    //Variables
    BIO *abio;
    BIO *cbio;
    BIO *acpt;
    BIO *outbio;
    int bytesread;
    int buffer_size = 1024;
    char buffer[buffer_size];
    int connection_status;
    int write_status;
    const char *filename = "/home/ivan/CLionProjects/EHN_Prac1/webpage_1.txt";
    const char *certificate_file = "/home/ivan/EHN/webServCert.crt";
    const char *private_file = "/home/ivan/EHN/webServ.key";
    SSL_CTX *ctx;
    SSL *ssl;


    //SSL initialize
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx==NULL){
        printf("failed to create SSL context\n");
        return 0;
    }

    SSL_CTX_use_certificate_file(ctx, certificate_file, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, private_file, SSL_FILETYPE_PEM);

    while(1){
        abio = BIO_new_ssl(ctx, 0);
        if (abio == NULL){
            printf("failed retrieving the BIO object\n");
            return 0;
        }

        //Disable retires
        BIO_get_ssl(abio, &ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        //Buffer
        cbio = BIO_new(BIO_f_buffer());

        //Chain
        abio = BIO_push(cbio, abio);

        acpt = BIO_new_accept("4433");

        BIO_set_accept_bios(acpt, abio);
        outbio = BIO_new_fd(stdout, BIO_NOCLOSE);


        //BIO wait and setup
        connection_status = connect(acpt);

        abio = BIO_pop(acpt);

        BIO_free_all(acpt);

        if(BIO_do_handshake(abio) <= 0){
            printf("failed handshake, wash hands and try again\n");
        }

        BIO_puts(abio, "HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\n");
        BIO_puts(abio, "\r\nConnection Established\r\nRequest headers:\r\n");
        BIO_puts(abio, "--------------------------------------------------\r\n");

        for(;;) {
            bytesread = BIO_gets(abio, buffer, buffer_size);
            if(bytesread <= 0) break;
            BIO_write(abio, buffer, bytesread);
            BIO_write(outbio, buffer, bytesread);
            /* Look for blank line signifying end of headers*/
            if((buffer[0] == '\r') || (buffer[0] == '\n')) break;
        }

        BIO_puts(abio, "--------------------------------------------------\r\n");
        BIO_puts(abio, "\r\n");

        BIO_flush(abio);
        BIO_free_all(abio);
    }












//    pthread_t thread1, thread2;
//    char *message1 = "Thread 1";
//    char *message2 = "Thread 2";
//    int  iret1, iret2;
//
//    /* Create independent threads each of which will execute function */
//
//    iret1 = pthread_create( &thread1, NULL, print_message_function, (void*) message1);
//    iret2 = pthread_create( &thread2, NULL, print_message_function, (void*) message2);
//
//    /* Wait till threads are complete before main continues. Unless we  */
//    /* wait we run the risk of executing an exit which will terminate   */
//    /* the process and all threads before the threads have completed.   */
//
//    pthread_join( thread1, NULL);
//    pthread_join( thread2, NULL);
//
//    printf("Thread 1 returns: %d\n",iret1);
//    printf("Thread 2 returns: %d\n",iret2);
//    exit(0);
}

void *print_message_function( void *ptr )
{
    char *message;
    message = (char *) ptr;
    printf("%s \n", message);
}


int connect(BIO *bio){
    if (BIO_do_accept(bio)<=0){
        printf("error setting up listening socket\n");
        BIO_free(bio);
        return 0;
    }


    BIO_set_nbio_accept(bio, 0);
    if (BIO_do_accept(bio)<=0){
        printf("error accepting the socket\n");
        BIO_free(bio);
        return 0;
    }
    return 1;
}


int write_page(BIO *bio, const char *page){
    FILE *f;
    int bytesread;
    unsigned char buf[512];

    f = fopen(page, "r");
    if(!f){
        printf("could not open page\n");
        return 0;
    }

    while (1){
        bytesread = fread(buf, sizeof(unsigned char), 512, f);

        if (bytesread == 0)
            break;

        if(BIO_write(bio, buf, bytesread) <= 0){
            printf("write failed\n");
            break;
        }
    }

    fclose(f);

}



