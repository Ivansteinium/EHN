//
// Created by ivan on 2020/02/18.
//

#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <unistd.h>
#include <string.h>

#define MAX_REQ_LEN 255


#define MAX_REQ_LEN 255


int main()
{
    BIO *sbio, *out;
    int len;
    char tmpbuf[1024];
    char filename[MAX_REQ_LEN - 16];
    char request[MAX_REQ_LEN];
    char *isHTML = NULL;
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

    if(!SSL_CTX_load_verify_locations(ctx, "../keys/cert.crt", NULL))
        printf("Failed to load verify location");

    sbio = BIO_new_ssl_connect(ctx);

    BIO_get_ssl(sbio, &ssl);

    if(!ssl)
        fprintf(stderr, "Can't locate SSL pointer\n");
    /* whatever ... */

    /* Don't want any retries */
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    /* We might want to do other things with ssl here */

    BIO_set_conn_hostname(sbio, "0.0.0.0:5000");

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if(BIO_do_connect(sbio) <= 0)
    {
        printf("Error connecting to server:\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
    }

    if(BIO_do_handshake(sbio) <= 0)
        printf("Error establishing SSL connection\n");

/* Could examine ssl here to get connection info */

/*    BIO_puts(sbio, "GET / HTTP/1.0\n\n");
    for (;;)
    {
        len = BIO_read(sbio, tmpbuf, 1024);
        if (len <= 0) break;
        BIO_write(out, tmpbuf, len);
    }*/
    sleep(1);

    BIO_puts(sbio, "GET / HTTP/1.0\n\n");
    while(1)
    {
        len = BIO_read(sbio, tmpbuf, 1024);
        if(len <= 0) break;
        tmpbuf[len] = '\0';
        printf("%s", tmpbuf);
    }

    printf("\n\n");
    BIO_reset(sbio);

    while(1)
    {
        printf("Please type the name of the file that you want to request:");
        fgets(filename, MAX_REQ_LEN, stdin);
        printf("getting %s \n", filename);
        isHTML = strstr(filename, ".html");
        filename[strlen(filename) - 1] = '\0';

        sprintf(request, "GET /%s HTTP/1.0\n\n", filename);

//        sbio = BIO_new_ssl_connect(ctx);
        if(BIO_do_connect(sbio) <= 0)
        {
            printf("Error connecting to server:\n");
            printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        }

        if(BIO_do_handshake(sbio) <= 0)
            printf("Error establishing SSL connection\n");

        BIO_puts(sbio, request);
//        sleep(1);
        if(isHTML == NULL)
        {
            int bytesread = 0;
            char buffer[513]; //has to be 1 bigger than 512(send buffer size) otherwise corrupt. dont know why
            char local_filename[MAX_REQ_LEN - 16];
            FILE *fptr;
            char *messagepos = NULL;

            sprintf(local_filename, "../%s", filename);
            fptr = fopen(local_filename, "w");
            printf("writing file to: %s \n", local_filename);
            if(fptr == NULL)
            {
                printf("Error opening file");
                return 1;
            } else
            {
                while(1)
                {
                    bytesread = BIO_read(sbio, buffer, sizeof(buffer));
                    if(bytesread == 0)
                    {
                        printf("server closed the connection\n");
                        break;
                    }
                    messagepos = strstr(buffer, "\n\n");
                    if(messagepos != NULL)
                    {
                        messagepos +=2;
                        fwrite(messagepos, sizeof(char), bytesread - (messagepos - buffer), fptr);
                    } else
                        fwrite(buffer, sizeof(char), bytesread, fptr);
//                    usleep(100);
                }
            }
            fclose(fptr);
        } else
        {
            while (1)
            {
                len = BIO_read(sbio, tmpbuf, 1024);
                if (len <= 0) break;
                tmpbuf[len] = '\0';
                printf("%s", tmpbuf);
            }
        }
        printf("\n\n");
        BIO_reset(sbio);
    }

    //image send demo
/*    int bytesread = 0;
    char buffer[103900];
    FILE *fptr;
    fptr = fopen("../1.jpg", "wb");
    if (fptr == NULL)
    {
        printf("Error opening file");
        return 1;
    } else
    {
        while (1)
        {
            bytesread = BIO_read(sbio, buffer, sizeof(buffer));
            if (bytesread == 0)
            {
                printf("server closed the connection\n");
                break;
            }
            fwrite(buffer, sizeof(char), bytesread, fptr);
        }
    }
    fclose(fptr);*/

    BIO_free_all(sbio);
    BIO_free(out);
    return 0;
}


