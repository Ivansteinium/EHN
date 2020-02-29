#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>


#pragma clang diagnostic ignored "-Wmissing-noreturn"


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


struct pthread_args
{
    BIO *abio;
    int thread_number;
};


void *new_client_connection(void *ptr);


pthread_t *double_size(pthread_t *old_clients, int current_size);


int write_page(BIO *bio, const char *page, const char *filename);


int readMedia();


int connect(BIO *bio);


int main()
{
    //Variables
    int i;
    BIO *abio;
    BIO *cbio;
    BIO *acpt;
//    BIO *outbio;
//    unsigned long bytesread;
//    int buffer_size = 103900;
//    uint8_t buffer[buffer_size];
//    int write_status;
//    const char *filename = "../webpage_1.txt";
    int port_num = 5000;
    int connection_status;
    const char *certificate_file = "../keys/webServCert.crt";
    const char *private_file = "../keys/webServ.key";
    SSL_CTX *ctx;
    SSL *ssl;

    //Dynamic Threads
    int max_clients = 4;
    int current_clients = 0;
    pthread_t *client_threads = (pthread_t *) malloc(max_clients * sizeof(pthread_t));

    // Initialize the server
    printf("Starting Server...\n\n");

    //SSL initialize
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();

    // supply password to decrypt key
    // https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_set_default_passwd_cb.htmlls

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL)
    {
        printf("Failed to create SSL context\n");
        return EXIT_FAILURE;
    }

    SSL_CTX_use_certificate_file(ctx, certificate_file, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, private_file, SSL_FILETYPE_PEM);
    readMedia();

    abio = BIO_new_ssl(ctx, 0);
    if (abio == NULL)
    {
        printf("Failed retrieving the BIO object\n");
        return EXIT_FAILURE;
    }

    // Disable retires
    BIO_get_ssl(abio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    // Buffer
    cbio = BIO_new(BIO_f_buffer());
    // Chain
    abio = BIO_push(cbio, abio);
    acpt = BIO_new_accept(ITOA(port_num++));

    // Server initialization is complete
    printf("Server Running\n\n");

    BIO_set_accept_bios(acpt, abio);
//    outbio = BIO_new_fd(stdout, BIO_NOCLOSE);

    // BIO wait and setup
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

        // Get new client
        abio = BIO_pop(acpt);

        // Allocate the new client to a thread

        // Double threads when max clients is reached
        if (current_clients == max_clients)
        {
            client_threads = double_size(client_threads, max_clients);
            max_clients = max_clients * 2;
        }

        current_clients++;

        struct pthread_args *args = (struct pthread_args*) malloc (sizeof(struct pthread_args));
        args->abio = abio;
        args->thread_number = current_clients - 1;

        // Create a new thread for the client
        pthread_create(&client_threads[current_clients - 1],
                NULL,
                new_client_connection,
                (void *) args);

/*        temp = pthread_create( &thread1, NULL, new_client_connection, (void*) abio);
        pthread_join(client_threads[num_clients-1], NULL);

        if (BIO_do_handshake(abio) <= 0)
        {
            printf("failed handshake, wash hands and try again\n");
            printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        }

        BIO_puts(abio, "HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\n");
        BIO_puts(abio, "\r\nConnection Established\r\nRequest headers:\r\n");
        BIO_puts(abio, "--------------------------------------------------\r\n");

        while (1)
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

        FILE *file;
        file = fopen("../Media_files/files_list.html", "w");

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
            fputs(temp,file);
        }
        fputs("</html>\r\n",file);
        BIO_puts(abio, "</html>");
        fclose(file);

        file = fopen("../Media_files/test.html", "r");
        if (file == NULL)
            printf("Error opening file\n");
        else
        {
            while (1)
            {
                bytesread = fread(buffer, sizeof(char), buffer_size, file);
                if (bytesread <= 0) break;
                SSL_write(abio, buffer, bytesread);
                printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
                BIO_write(outbio, buffer, bytesread);
                printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
                // Look for blank line signifying end of headers
            }
        }

        fclose(file);
        write_page(abio,"../Media_files/test.html", 1);
        sleep(1); */
    }

/*    pthread_join(client_threads[num_clients - 1], NULL);
    sleep(1);
    BIO_flush(abio);
    BIO_free_all(acpt);
    BIO_free_all(abio); */
}

// This thread is spawned every time a new connection request is received
void *new_client_connection(void *ptr)
{
    struct pthread_args *args = (struct pthread_args *) ptr;
    BIO *client = args->abio;

    printf("Connection %d Opened\n", args->thread_number);

    if (BIO_do_handshake(client) <= 0)
    {
        printf("Handshake Failed\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        return EXIT_FAILURE;
    }

    char tempbuf[256];
    char *startpos;
    char *endpos;
    char filename[256];

    while (1)  // Service the client's requests
    {
        if (BIO_gets(client, tempbuf, 256) > 0)
        {   //read request and send the page if valid
            printf("Received: %s", tempbuf);
            startpos = strstr(tempbuf, "GET ");
            startpos += 4;
            endpos = strstr(tempbuf, " HTTP");
            if (startpos == NULL || endpos == NULL)  // Invalid GET request
            {
                printf("invalid request received\n");
                BIO_puts(client,"Invalid request\n");
            } else  // Valid GET request
            {
                // Get the requested item from the string
                strncpy(filename, startpos, endpos - startpos);

                if (strcmp(filename, "/") == 0)  // Write the home page
                    write_page(client, "../Media_files/test.html", "html");
                else
                {   // Not home page
                    // Delete leading "/"
                    startpos += 1;
                    strncpy(filename, startpos, endpos - startpos);
                    filename[endpos - startpos] = '\0';

                    // Search for file and send it if present
                    int i = 0;
                    int valid = 0;
                    for (i = 0; i < numMediaItems + 1; i++)
                    {
                        if (strcmp(filename, MediaItems[i]) == 0)
                        {
                            valid = 1;
                            break;
                        }
                    }

                    if (!valid)
                    {   // If item is not present, display error
                        printf("Error: Requested item not found\n");
                        BIO_puts(client,"Error: Requested item not found\r\n");
                    } else
                    {   // Send file
                        char sendname[256];
                        sprintf(sendname, "%s%s", "../Media_files/", filename);
                        if (strstr(tempbuf, "html") == NULL)
                            write_page(client, sendname, filename);
                        else
                            write_page(client, sendname, "html");
                    }
                }
            }

            BIO_flush(client);
            BIO_reset(client);
        } else
            break;
    }

    printf("Connection %d Closed\n", args->thread_number);
    free(args);
    return EXIT_SUCCESS;
}


// Attempt to setup to a socket and then wait for the client to connect to it
int connect(BIO *bio)
{
    if (BIO_do_accept(bio) <= 0)
    {
        printf("Error setting up listening socket\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        BIO_free(bio);
        return EXIT_SUCCESS;
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

    return EXIT_FAILURE;
}


// Read all the contents of the Media_files folder for use later in GET requests
int readMedia()
{
    DIR *directory;
    struct dirent *ent;
    directory = opendir("../Media_files");
    if (directory != NULL)
    {   // Print all the files and directories within directory
        while ((ent = readdir(directory)) != NULL)
        {
            strcpy(MediaItems[numMediaItems], ent->d_name);
            numMediaItems++;
        }

        closedir(directory);
    } else  // Could not open directory
        return EXIT_FAILURE;

    FILE *file;
    file = fopen("../Media_files/files_list.html", "w");

    // Generate an html file showing all the items available on the server and send it to the client

    int i = 0;
    char temp[maxMediaNameSize];
//    fputs("HTTP/1.1 200 OK\n"
//          "Content-Type: text/html; charset=utf-8\n"
//          "Connection: close\n"
//          "Content-Length: 500\n",file);
//    fputs("\r\n",file);
    fputs("<html>\r\n", file);
    for (i = 2; i < numMediaItems; i++)
    {   // Build the html link command and send it to the client
        strcpy(temp, "<p><a href=\"");
        strcat(temp, MediaItems[i]);
        strcat(temp, "\">");
        strcat(temp, MediaItems[i]);
        strcat(temp, "</a></p>\r\n");
        fputs(temp, file);
    }
    fputs("</html>\r\n", file);
    fclose(file);
    return EXIT_SUCCESS;
}


// Send some file to the client
int write_page(BIO *bio, const char *page, const char* filename)
{
    FILE *file;
    unsigned long bytesread;
    char buf[512];
    char html_reply[100]; /*= "HTTP/1.1 200 OK\n"
                           "Content-Type: text/html; charset=utf-8\n"
                           "Connection: close\n"
                           "Content-Length: 500\n\r\n";*/

    if(strcmp(filename, "html") != 0)
    {
        sprintf(html_reply, "HTTP/1.1 200 OK\n"
                            "Content-Disposition: attachment; filename=\"%s\" \n\n", filename);
//        strcpy(html_reply, "HTTP/1.1 200 OK\n"
//                           "Content-Disposition: attachment;");
    } else
    {
        sprintf(html_reply, "HTTP/1.1 200 OK\n"
                            "Content-Type: text/html; charset=utf-8\n"
                            "Connection: close\n"
                            "Content-Length: 500\n\r\n");
    }


    file = fopen(page, "r");
    if (!file)
    {
        printf("could not open page\n");
        return EXIT_FAILURE;
    }

//    if (strcmp(filename, "html") == 0) // If the file is an HTML file, include the header
        BIO_write(bio, html_reply, strlen(html_reply));

    bytesread = fread(buf, sizeof(char), 512, file);
    while (bytesread > 0)
    {   // Send the file in blocks of 512 Bytes
        if (BIO_write(bio, buf, bytesread) <= 0)
        {
            printf("write failed\n");
            printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }
        bytesread = fread(buf, sizeof(char), 512, file);
    }

    fclose(file);
    return EXIT_SUCCESS;
}


// When the maximum amount of threads are created, create a new array with double the capacity,
// copy the old threads to the new array and delete the old array
pthread_t *double_size(pthread_t *old_clients, int current_size)
{
    printf("Clients list doubled\n");

    pthread_t *new_clients;
    new_clients = (pthread_t *) malloc((current_size * 2) * sizeof(pthread_t));
    int i;
    for (i = 0; i < current_size; ++i)
        new_clients[i] = old_clients[i];
    free(old_clients);
    return new_clients;
}
