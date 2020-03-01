#include "Server.h"


#pragma clang diagnostic ignored "-Wmissing-noreturn"


int main(int argc, char *argv[])
{
    //Variables
    BIO *abio;
    BIO *cbio;
    BIO *acpt;
    int port_num = 5000;
    char certificate_file[200];
    char private_file[200];

    // Setup certificate file paths
    if (argc < 3)
    {
        strcpy(certificate_file,"../keys/webServCert.crt");
        strcpy(private_file,"../keys/webServ.key");
    } else
    {
        strcpy(certificate_file,argv[1]);
        strcpy(private_file,argv[2]);
    }

    SSL_CTX *ctx;
    SSL *ssl;

    // Dynamic Threads
    int max_clients = 4;
    int current_clients = 0;
    pthread_t *client_threads = (pthread_t *) malloc(max_clients * sizeof(pthread_t));

    // Initialize the server
    printf("Starting Server...\n\n");

    //SSL initialize
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();

    // supply password to decrypt key if key is encrypted
    // https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_set_default_passwd_cb.htmlls

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL)
    {
        printf("Failed to create SSL context\n");
        return EXIT_FAILURE;
    }

    SSL_CTX_use_certificate_file(ctx, certificate_file, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, private_file, SSL_FILETYPE_PEM);
    read_media();

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
    char temp[10];
    acpt = BIO_new_accept(itoa(temp, port_num));

    // Server initialization is complete
    printf("Server Running\n\n");

    BIO_set_accept_bios(acpt, abio);

    // BIO wait and setup
    if (connect(acpt) == EXIT_FAILURE)
        return EXIT_FAILURE;

    while (1)
    {   // Set the SSL to non-blocking mode continuously attempt to setup the socket
        BIO_set_nbio_accept(acpt, 0);
        while (BIO_do_accept(acpt) <= 0)
        {
            printf("error accepting the socket\n");
            printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
            BIO_reset(acpt);
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

        // Setup the argument information
        struct pthread_args *args = (struct pthread_args *) malloc(sizeof(struct pthread_args));
        args->abio = abio;
        args->thread_number = current_clients - 1;

        // Create a new thread for the client
        pthread_create(&client_threads[current_clients - 1],
                       NULL,
                       new_client_connection,
                       (void *) args);
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
    // Retrieve the SSL object and thread number from the argument
    struct pthread_args *args = (struct pthread_args *) ptr;
    BIO *client = args->abio;

    printf("Connection %d Opened\n", args->thread_number);

    // Perform the SSL handshake
    if (BIO_do_handshake(client) <= 0)
    {   // The handshake was not successful
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
            if (startpos == NULL || endpos == NULL)
            {   // Invalid GET request
                printf("invalid request received\n");
                BIO_puts(client, "Invalid request\n");
            } else  // Valid GET request
            {
                // Get the requested item from the string
                strncpy(filename, startpos, endpos - startpos);

                if (strcmp(filename, "/") == 0)  // Write the home page
                    write_page(client, "../Media_files/index.html", "html");
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
                    {   // If item is not present, display error and notify the client
                        printf("Error: Requested item not found\n");
                        BIO_puts(client, "Error: Requested item not found\r\n");
                    } else
                    {   // Send file
                        char sendname[256];
                        sprintf(sendname, "%s%s", "../Media_files/", filename);
                        if (strstr(tempbuf, "html") == NULL)
                            write_page(client, sendname, filename); // General file
                        else
                            write_page(client, sendname, "html"); // HTML file
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
    // Setup the SSL socket in blocking mode
    if (BIO_do_accept(bio) <= 0)
    {   // The setup operation was not successful
        printf("Error setting up listening socket\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        BIO_free(bio);
        return EXIT_FAILURE;
    }

/*     Set the SSL to non-blocking mode continuously attempt to setup the socket.
     This is done since the socket takes time to be released by the system after use.
     Only an issue if the server is run several times in quick succession*/
    BIO_set_nbio_accept(bio, 0);
    while (BIO_do_accept(bio) <= 0)
    {   // Not yet accepted
        printf("Error accepting the socket\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        BIO_reset(bio);
//        BIO_set_nbio_accept(bio, 0);
        sleep(1);
    }

    return EXIT_SUCCESS;
}


// Read all the contents of the Media_files folder for use later in GET requests
int read_media()
{
    DIR *directory;
    struct dirent *ent;
    directory = opendir("../Media_files");
    if (directory != NULL)
    {   // Read all the files and directories within directory
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

    // Generate an html file showing all the items available on the server and save the html file as files_list.html

    int i = 0;
    char temp[maxMediaNameSize];
    fputs("<html>\r\n", file);
    for (i = 2; i < numMediaItems; i++)
    {   // Build the html links to all the files
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
int write_page(BIO *bio, const char *page, const char *filename)
{
    FILE *file;
    unsigned long bytesread;
    char buf[512];
    char html_reply[100];

    if (strcmp(filename, "html") != 0)
    {
        sprintf(html_reply, "HTTP/1.1 200 OK\n"
                            "Content-Disposition: attachment; filename=\"%s\" \n\n", filename);
    } else
    {
        sprintf(html_reply, "HTTP/1.1 200 OK\n"
                            "Content-Type: text/html; charset=utf-8\n"
                            "Connection: close\n"
                            "Content-Length: 500\n\r\n");
    }


    file = fopen(page, "r");
    if (!file)
    {   // File to be written not found
        printf("Could not open page to be written\n");
        return EXIT_FAILURE;
    }

    // Send the correct file header
    BIO_write(bio, html_reply, strlen(html_reply));

    bytesread = fread(buf, sizeof(char), 512, file);
    while (bytesread > 0)
    {   // Send the file in blocks of 512 Bytes
        if (BIO_write(bio, buf, bytesread) <= 0)
        {   // The SSL object did not accept the data
            printf("Write failed\n");
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
    pthread_t *new_clients;
    new_clients = (pthread_t *) malloc((current_size * 2) * sizeof(pthread_t));
    int i;
    for (i = 0; i < current_size; ++i)
        new_clients[i] = old_clients[i];
    free(old_clients);
    return new_clients;
}


// Use sprintf to convert between integer and string
char *itoa(char *dest, int i)
{
    sprintf(dest, "%d", i);
    return dest;
}
