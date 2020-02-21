#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>


char *my_itoa(char *dest, int i)
{
    sprintf(dest, "%d", i);
    return dest;
}


#define ITOA(n) my_itoa((char [41]) { 0 }, (n) )
#define maxMediaItems  100
#define maxMediaNameSize  256
char MediaItems[maxMediaItems][maxMediaNameSize];
int numMediaItems = 0;

void *print_message_function(void *ptr);


void *new_client_connection(void *ptr);


pthread_t *double_size(pthread_t *old_clients, int current_size);


int write_page(BIO *bio, const char *page, int html);


int readMedia();


int connect(BIO *bio);


int main()
{
    //Variables
    BIO *abio;
    BIO *cbio;
    BIO *acpt;
    BIO *outbio;
    int port_num = 5000;
    unsigned long bytesread;
    int buffer_size = 103900;
    uint8_t buffer[buffer_size];
    int connection_status;
    int write_status;
    const char *filename = "../webpage_1.txt";
    const char *certificate_file = "../keys/webServCert.crt";
    const char *private_file = "../keys/webServ.key";
    SSL_CTX *ctx;
    SSL *ssl;

    //Threads
    pthread_t thread1;
    int iret1;

    //Dynamic Threads
    pthread_t *temp, *client_threads;
    int max_clients = 4, num_clients = 0;
    client_threads = (pthread_t *) malloc(max_clients * sizeof(pthread_t));

    //SSL initialize
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();

    // supply password to decrypt key
    // https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_set_default_passwd_cb.htmlls

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL)
    {
        printf("failed to create SSL context\n");
        return 0;
    }

    SSL_CTX_use_certificate_file(ctx, certificate_file, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, private_file, SSL_FILETYPE_PEM);
    readMedia();

    abio = BIO_new_ssl(ctx, 0);
    if (abio == NULL)
    {
        printf("failed retrieving the BIO object\n");
    }

    //Disable retires
    BIO_get_ssl(abio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    //Buffer
    cbio = BIO_new(BIO_f_buffer());

    //Chain
    abio = BIO_push(cbio, abio);

    acpt = BIO_new_accept(ITOA(port_num++));

    BIO_set_accept_bios(acpt, abio);
//    outbio = BIO_new_fd(stdout, BIO_NOCLOSE);

    //BIO wait and setup
    connection_status = connect(acpt);
    if (connection_status == 0)
        return 0;

    while (1)
    {
        BIO_set_nbio_accept(acpt, 0);
        while (BIO_do_accept(acpt) <= 0)
        {
            printf("error accepting the socket\n");
            printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
            BIO_reset(acpt);
//            BIO_set_nbio_accept(bio, 0);
//            sleep(1);
        }

        abio = BIO_pop(acpt);
        num_clients++;

        //Double threads if max clients os reached
        if (num_clients == max_clients)
        {
            client_threads = double_size(client_threads, max_clients);
            max_clients = max_clients * 2;
        }

        // Create a new thread for the client
        pthread_create(&client_threads[num_clients - 1], NULL, new_client_connection, (void *) abio);


/*        iret1 = pthread_create( &thread1, NULL, new_client_connection, (void*) abio);
        pthread_join(client_threads[num_clients-1], NULL);

        if (BIO_do_handshake(abio) <= 0)
        {
            printf("failed handshake, wash hands and try again\n");
            printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        }

        BIO_puts(abio, "HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\n");
        BIO_puts(abio, "\r\nConnection Established\r\nRequest headers:\r\n");
        BIO_puts(abio, "--------------------------------------------------\r\n");

        for (;;)
        {
            bytesread = BIO_gets(abio, buffer, buffer_size);
            if (bytesread <= 0) break;
            BIO_write(abio, buffer, bytesread);
            BIO_write(outbio, buffer, bytesread);
            // Look for blank line signifying end of headers
            if ((buffer[0] == '\r') || (buffer[0] == '\n')) break;
        }

        BIO_puts(abio, "--------------------------------------------------\r\n");
        BIO_puts(abio, "\r\n");

        FILE *fptr;
        fptr = fopen("../Media_files/files_list.html", "w");

        //generate an html file showing all the items available on the server and send it to the client

        int i = 0;
        char temp[maxMediaNameSize];
        for (i = 2; i < numMediaItems; i++)
        {
            //build the html link command and send it to the client
            strcpy(temp, "<a href=\"");
            strcat(temp, MediaItems[i]);
            strcat(temp, "\">");
            strcat(temp, MediaItems[i]);
            strcat(temp, "</a>\r\n");
            fputs(temp,fptr);
        }
        fputs("</html>\r\n",fptr);
        BIO_puts(abio, "</html>");
        fclose(fptr);

        fptr = fopen("../Media_files/test.html", "r");
        if (fptr == NULL)
        {
            printf("Error opening file\n");
        } else
        {
            for (;;)
            {
                bytesread = fread(buffer, sizeof(char), buffer_size, fptr);
                if (bytesread <= 0) break;
                SSL_write(abio, buffer, bytesread);
                printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
                BIO_write(outbio, buffer, bytesread);
                printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
                // Look for blank line signifying end of headers
            }
        }
        fclose(fptr);

        write_page(abio,"../Media_files/test.html", 1);


       sleep(1);*/
    }

/*    pthread_join(client_threads[num_clients - 1], NULL);
    sleep(1);
    BIO_flush(abio);
    BIO_free_all(acpt);
    BIO_free_all(abio);

    //example threading code
    pthread_t thread1, thread2;
    char *message1 = "Thread 1";
    char *message2 = "Thread 2";
    int  iret1, iret2;

    // Create independent threads each of which will execute function

    iret1 = pthread_create( &thread1, NULL, print_message_function, (void*) message1);
    iret2 = pthread_create( &thread2, NULL, print_message_function, (void*) message2);

    // Wait till threads are complete before main continues. Unless we  //
    // wait we run the risk of executing an exit which will terminate   //
    // the process and all threads before the threads have completed.   //

    pthread_join( thread1, NULL);
    pthread_join( thread2, NULL);

    printf("Thread 1 returns: %d\n",iret1);
    printf("Thread 2 returns: %d\n",iret2);
    exit(0);*/
}


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"


void *print_message_function(void *ptr)
{
    char *message;
    message = (char *) ptr;
    printf("%s \n", message);
}


#pragma clang diagnostic pop

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"

// This thread is spawned every time a new connection request is received
void *new_client_connection(void *ptr)
{
    BIO *client;
    client = (BIO *) ptr;
    if (BIO_do_handshake(client) <= 0)
    {
        printf("failed handshake, wash hands and try again\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
    }
    char tempbuf[256];
    char *startpos;
    char *endpos;
    char filename[256];

    while (1)
    {
        //read request and send the page if valid
        if (BIO_gets(client, tempbuf, 256) > 0)
        {
            printf("Received: %s \r\n", tempbuf);
            startpos = strstr(tempbuf, "GET ");
            startpos += 4;
            endpos = strstr(tempbuf, " HTTP");
            if (startpos == NULL || endpos == NULL)
            {
                printf("invalid request received");
            } else
            {
                // Get the requested item from the string
                strncpy(filename, startpos, endpos - startpos);

                if (strcmp(filename, "/") == 0)
                { //write the home page
                    write_page(client, "../Media_files/test.html", 1);
                } else
                {
                    //delete leading "/"
                    startpos += 1;
                    strncpy(filename, startpos, endpos - startpos);
                    filename[endpos - startpos] = '\0';

                    //search for file and send it if present
                    int i = 0;
                    unsigned char valid = 0;
                    for (i = 0; i < numMediaItems + 1; i++)
                    {
                        if (strcmp(filename, MediaItems[i]) == 0)
                        {
                            valid = 1;
                            break;
                        }
                    }
                    if (!valid)
                    { // If item is not present, display error
                        printf("Error: Requested item not found\r\n");
                    } else
                    { //send file
                        char sendname[256];
                        sprintf(sendname, "%s%s", "../Media_files/", filename);
                        write_page(client, sendname, 1);
                    }
                }
            }

            BIO_flush(client);
            BIO_reset(client);
        } else
            break;
    }
}


#pragma clang diagnostic pop

// Attempt to setup to a socket and then wait for the client to connect to it
int connect(BIO *bio)
{
    if (BIO_do_accept(bio) <= 0)
    {
        printf("Error setting up listening socket\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        BIO_free(bio);
        return 0;
    }

    BIO_set_nbio_accept(bio, 0);
    while (BIO_do_accept(bio) <= 0)
    {
        printf("Error accepting the socket\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        BIO_reset(bio);
//        BIO_set_nbio_accept(bio, 0);
        sleep(1);
    }
    return 1;
}

// Send some file to the client
int write_page(BIO *bio, const char *page, int html)
{
    FILE *f;
    unsigned int bytesread;
    unsigned char buf[512];
    unsigned char html_reply[100] = "HTTP/1.1 200 OK\n"
                                    "Content-Type: text/html; charset=utf-8\n"
                                    "Connection: close\n"
                                    "Content-Length: 500\n\r\n";

    f = fopen(page, "r");
    if (!f)
    {
        printf("could not open page\n");
        return EXIT_FAILURE;
    }

    if (html) // If the file is an HTML file, include the header
        BIO_write(bio, html_reply, 95);

    while (1)
    { // Send the file in blocks of 512 Bytes
        bytesread = fread(buf, sizeof(unsigned char), 512, f);

        if (bytesread == 0)
            break;

        if (BIO_write(bio, buf, bytesread) <= 0)
        {
            printf("write failed\n");
            printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }
    }

    fclose(f);
    return EXIT_SUCCESS;
}

// Read all the contents of the Media_files folder for use later in GET requests
int readMedia()
{
    DIR *directory;
    struct dirent *ent;
    directory = opendir("../Media_files");
    if (directory != NULL)
    {
        /* print all the files and directories within directory */
        while ((ent = readdir(directory)) != NULL)
        {
            strcpy(MediaItems[numMediaItems], ent->d_name);
            numMediaItems++;
        }

        closedir(directory);
    } else
    {
        /* could not open directory */
        return EXIT_FAILURE;
    }

    FILE *fptr;
    fptr = fopen("../Media_files/files_list.html", "w");

    //generate an html file showing all the items available on the server and send it to the client

    int i = 0;
    char temp[maxMediaNameSize];
//    fputs("HTTP/1.1 200 OK\n"
//          "Content-Type: text/html; charset=utf-8\n"
//          "Connection: close\n"
//          "Content-Length: 500\n",fptr);
//    fputs("\r\n",fptr);
    fputs("<html>\r\n", fptr);
    for (i = 2; i < numMediaItems; i++)
    {
        //build the html link command and send it to the client
        strcpy(temp, "<p><a href=\"");
        strcat(temp, MediaItems[i]);
        strcat(temp, "\">");
        strcat(temp, MediaItems[i]);
        strcat(temp, "</a></p>\r\n");
        fputs(temp, fptr);
    }
    fputs("</html>\r\n", fptr);
    fclose(fptr);
    return EXIT_SUCCESS;
}

// When the maximum amount of threads are created, create a new array with double the capacity,
// copy the old threads to the new array and delete the old array
pthread_t *double_size(pthread_t *old_clients, int current_size)
{
    pthread_t *temp;
    temp = (pthread_t *) malloc((current_size * 2) * sizeof(pthread_t));
    for (int i = 0; i < current_size; ++i)
    {
        temp[i] = old_clients[i];
    }
    free(old_clients);
    return temp;
}
