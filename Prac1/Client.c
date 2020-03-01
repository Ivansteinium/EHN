#include "Client.h"


int main(int argc, char * argv[])
{
    BIO *sbio;
    BIO *out;
    unsigned long bytesread;
    char buffer[513]; // has to be 1 bigger than send buffer size for \0
    char filename[MAX_REQ_LEN - 16];
    char request[MAX_REQ_LEN];
    int isHTML = 0;
    SSL_CTX *ctx;
    SSL *ssl;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();
    ctx = SSL_CTX_new(SSLv23_client_method());

    /* We'd normally set some stuff like the verify paths and
     * mode here because as things stand this will connect to
     * any server whose certificate is signed by any CA.
     */

    // Setup certificate file paths
    if (argc < 2)
    {
        if (!SSL_CTX_load_verify_locations(ctx, "../keys/cert.crt", NULL))
        {
            printf("Failed to load verify location\n");
            return EXIT_FAILURE;
        }
    } else
    {
        if (!SSL_CTX_load_verify_locations(ctx, argv[1], NULL))
        {
            printf("Failed to load verify location\n");
            return EXIT_FAILURE;
        }
    }

    // Setup a new SSL connection
    sbio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(sbio, &ssl);

    if (!ssl)
    {
        printf("Can't locate SSL pointer\n");
        return EXIT_FAILURE;
    }

    // Disable retries
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    // We might want to do other things with ssl here
    // TODO: R: soos wat?

    // Attempt to connect to the server
    printf("Attempting to connect to server...\n\n");
    BIO_set_conn_hostname(sbio, "0.0.0.0:5000"); // Set the address and port of the server
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (BIO_do_connect(sbio) <= 0)
    {   // Connection to the server was not successful
        printf("Error connecting to server:\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        return EXIT_FAILURE;
    }

    // Perform the SSL handshake
    if (BIO_do_handshake(sbio) <= 0)
    {   // The handshake was not successful
        printf("Handshake Failed\n");
        return EXIT_FAILURE;
    }

    // Could examine ssl here to get connection info

/*    BIO_puts(sbio, "GET / HTTP/1.0\n\n");
    bytesread = BIO_read(sbio, buffer, sizeof(buffer));
    while (bytesread > 0)
    {
        BIO_write(out, buffer, bytesread);
        bytesread = BIO_read(sbio, buffer, sizeof(buffer));
    }*/
    sleep(1);

    // Print the home .html file to the terminal
    BIO_puts(sbio, "GET / HTTP/1.0\n");
    bytesread = BIO_read(sbio, buffer, sizeof(buffer));
    while (bytesread > 0)
    {   // While there are bytes to read, read them and print them to the terminal
        buffer[bytesread] = '\0';
        printf("%s", buffer);
        bytesread = BIO_read(sbio, buffer, sizeof(buffer));
    }

    clear_buffer(buffer, 513);
    printf("\n\n");
    BIO_reset(sbio);

    while (1)
    {   // In a loop, ask the user for a file to download from the server
        printf("Please type the name of the file that you want to request\n");
        printf("or type 'EXIT' to close: ");
        fgets(filename, MAX_REQ_LEN, stdin); // Wait for user input

        if (!strcmp(filename, "EXIT\n"))
            return EXIT_SUCCESS; // User terminated program

        printf("Getting %s \n", filename);
        isHTML = strstr(filename, ".html") != NULL; // File name contains ".html"?
        filename[strlen(filename) - 1] = '\0'; // Overwrite \n with \0
        sprintf(request, "GET /%s HTTP/1.0\n", filename);

        // Attempt to connect to the Server
        if (BIO_do_connect(sbio) <= 0)
        {   // Connection to the server was not successful
            printf("Error connecting to server:\n");
            printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        // Perform the SSL handshake
        if (BIO_do_handshake(sbio) <= 0)
        {   // The handshake was not successful
            printf("Handshake Failed\n");
            break;
        }

        // Send the GET request to the server
        BIO_puts(sbio, request);

        // Decide what to do with the response based on the file type
        if (!isHTML)
        {   // If general file, save as a new file
            char local_filename[MAX_REQ_LEN - 16];
            FILE *file;
            char *messagepos = NULL;
            int fileExists;

            sprintf(local_filename, "../%s", filename);
            file = fopen(local_filename, "w");
            printf("Writing file to: %s \n", local_filename);

            // Write the file to the new text file, piece by piece
            bytesread = BIO_read(sbio, buffer, sizeof(buffer));

            if (!strcmp("Error: Requested item not found\r\n", buffer))
            {   // Server says the file does not exist
                fileExists = 0;
                bytesread = 0;
            } else
                fileExists = 1;

            while (bytesread > 0)
            {   // While there are bytes to read, read them and write them to the file
                messagepos = strstr(buffer, "\n\n");
                if (messagepos != NULL)
                {
                    messagepos +=2;
                    fwrite(messagepos, sizeof(char), bytesread - (messagepos - buffer), file);
                } else
                    fwrite(buffer, sizeof(char), bytesread, file);
                bytesread = BIO_read(sbio, buffer, sizeof(buffer));
            }

            // No more response from the server
            printf("Server closed the connection\n");
            fclose(file);
            if (fileExists)
                printf("File download completed: %s \n", filename);
            else
            {   // Server returened error
                printf("Error: Requested item not found\n");
                remove(local_filename); // Delete the newly created file
            }
        } else
        {   // Simply print out the .html file to the terminal
            bytesread = BIO_read(sbio, buffer, sizeof(buffer));
            while (bytesread > 0)
            {   // While there are bytes to read, read them and print them to the terminal
                buffer[bytesread] = '\0';
                printf("%s", buffer);
                bytesread = BIO_read(sbio, buffer, sizeof(buffer));
            }
        }
        printf("\n\n");
        BIO_reset(sbio);
        clear_buffer(buffer, 513);
    }

/*    //image send demo
    unsigned long bytesread = 0;
    char buffer[103900];
    FILE *file;
    file = fopen("../1.jpg", "wb");
    if (file == NULL)
    {
        printf("Error opening file");
        return EXIT_FAILURE;
    } else
    {
        bytesread = BIO_read(sbio, buffer, sizeof(buffer));
        while (bytesread > 0)
        {
            fwrite(buffer, sizeof(char), bytesread, file);
            bytesread = BIO_read(sbio, buffer, sizeof(buffer));
        }
        printf("server closed the connection\n");
    }
    fclose(file);*/

    // Free all SSL connections
    BIO_free_all(sbio);
    BIO_free(out);
    return EXIT_SUCCESS;
}


// Clear any message buffer up to the specified point
void clear_buffer(char * buffer, int length)
{
    int i;
    for (i = 0; i < length; i ++)
        buffer[i] = 0;
}



