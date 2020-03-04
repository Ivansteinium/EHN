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

    // Greeting
    printf("EHN 410 Group 12 Practical 1: Server\n\n");

    if (DEBUG)
        printf("Server debugging enabled\n\n");

    // Setup certificate file paths
    // load the default values
    strcpy(certificate_file,"../keys/webServCert.crt");
    strcpy(private_file,"../keys/webServ.key");
    //Search for and apply the settings from command line arguments
    if (argc < 2)
        printf("Certificate parameters not given, using default values...\n");
    else
    {
        int x = 0;
        for (x = 1; x < argc; x++)
        {
            char * endpos = strstr(argv[x],"=")+1;
            if(strstr(argv[x],"cert=") != NULL)
                strcpy(certificate_file,endpos);
            else if(strstr(argv[x],"key=") != NULL)
                strcpy(private_file,endpos);
            else if(strstr(argv[x],"port=") != NULL)
                port_num = atoi(endpos);
            else
                printf("Invalid parameter: %s\n", argv[x]);
        }
    }

    SSL_CTX *ctx;
    SSL *ssl;

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

    // Set up server certificate and private key
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

    // Start the server thread
    SERVER_RUN = 1;
    pthread_t server;
    struct server_args *sv_args = (struct server_args *) malloc(sizeof(struct server_args));
    sv_args->acpt = acpt;
    sv_args->abio = abio;
    pthread_create(&server, NULL, server_thread, (void *) sv_args);

    // Server initialization is complete
    printf("Server Running on port %d\n", port_num);

    // Wait fot the user to stop the program
    int exit = 0;
    char input[100];
    while (!exit)
    {
        printf("Type 'EXIT' at any time to stop\n\n");
        fgets(input, 100, stdin); // Wait for user input

        if (!strcmp("EXIT\n", input))
            exit = 1;
    }

    // Stop the server thread
    SERVER_RUN = 0;
    pthread_join(server, NULL);

    return EXIT_SUCCESS;
}


// Create a thread to handle server requests so that main is not blocked
void *server_thread(void *ptr)
{
    struct server_args *sv_args = (struct server_args *) ptr;
    BIO * acpt = sv_args->acpt;
    BIO *abio = sv_args->abio;

    // Dynamic Threads for clients
    int max_clients = 4;
    int current_clients = 0;
    pthread_t *client_threads = (pthread_t *) malloc(max_clients * sizeof(pthread_t));

    /*  Set the SSL to non-blocking mode and continuously attempt to setup the socket.
        This is done since the socket takes time to be released by the system after use.
        Only an issue if the server is run several times in quick succession */
    BIO_set_accept_bios(acpt, abio);
    BIO_set_nbio_accept(acpt, 1);

    // The first call to BIO_do_accept() sets up the port to allow for connections
    if (BIO_do_accept(acpt) <= 0)
    {   // The setup operation was not successful
        printf("Error setting up listening socket\n");
        if (DEBUG)
            printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        BIO_free(acpt);
        return (void *) EXIT_FAILURE;
    }

    while (SERVER_RUN)
    {
        BIO_do_accept(acpt);

        // Get new client
        abio = BIO_pop(acpt);

        if (abio == NULL)
            continue; // Connect didn't happen yet, try again

        // Allocate the new client to a thread

        // Double threads when max clients is reached
        if (current_clients == max_clients)
        {
            client_threads = double_size(client_threads, max_clients);
            max_clients = max_clients * 2;
        }

        current_clients++;

        // Setup the argument information
        struct client_args *cl_args = (struct client_args *) malloc(sizeof(struct client_args));
        cl_args->abio = abio;
        cl_args->thread_number = current_clients - 1;

        // Create a new thread for the client
        pthread_create(&client_threads[current_clients - 1],
                NULL,
                new_client_connection,
                (void *) cl_args);
    }

    BIO_flush(abio);
    BIO_free_all(acpt);
    BIO_free_all(abio);
    free(sv_args);
    free(client_threads);

    return (void *) EXIT_SUCCESS;
}


// This thread is spawned every time a new connection request is received
void *new_client_connection(void *ptr)
{
    // Retrieve the SSL object and thread number from the argument
    struct client_args *cl_args = (struct client_args *) ptr;
    BIO *client = cl_args->abio;

    if (DEBUG)
        printf("Connection %d Opened\n", cl_args->thread_number);

    // Perform the SSL handshake
    if (BIO_do_handshake(client) <= 0)
    {   // The handshake was not successful
        printf("Handshake Failed\n");
        if (DEBUG)
            printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        return (void *) EXIT_FAILURE;
    }

    char tempbuf[256];
    char *startpos;
    char *endpos;
    char filename[256];
    char *spacepos;
    char *temp;

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

                // Look if spaces are present in the requested file
                spacepos = strstr(filename, "%20");
                if (spacepos)
                {   // %20 is present in the name, replace with spaces
                    int i = 0;
                    temp = filename;
                    while (spacepos)
                    {
                        while (*temp != *spacepos) // Write characters til %20
                            filename[i++] = *(temp++);
                        filename[i++] = ' '; // Write a space rather than %20
                        temp++; temp++; temp++; // Skip over the %20
                        spacepos = strstr(temp, "%20"); // Find the next occurrence
                    }

                    while (*temp != '\0')
                        filename[i++] = *(temp++);
                    filename[i++] = '\0';
                }

                if (strcmp(filename, "/") == 0)  // Write the home page
                    write_page(client, "../Media_files/index.html", "html");
                else
                {   // Not home page
                    // Delete leading "/"
                    temp = filename;
                    temp++;

                    // Search for file and send it if present
                    int i = 0;
                    int valid = 0;
                    for (i = 0; i < numMediaItems + 1; i++)
                    {
                        if (strcmp(temp, MediaItems[i]) == 0)
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
                        sprintf(sendname, "%s%s", "../Media_files/", temp);
                        if (strstr(tempbuf, "html") == NULL)
                            write_page(client, sendname, temp); // General file
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

    if (DEBUG)
        printf("Connection %d Closed\n", cl_args->thread_number);

    free(cl_args);
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
    char temp[256];
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
                            "Content-Length: 1000\n\r\n");
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
            if (DEBUG)
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
char *itoa(char *result, int number)
{
    sprintf(result, "%d", number);
    return result;
}
