#ifndef EHN_PRAC1_SERVER_H
#define EHN_PRAC1_SERVER_H

/// \defgroup servergroup Server
/// This module contains the entire server program. The server starts an SSL server with the specified key and
/// certificate files and listens for client connections. It also indexes all files stored in the Media_files folder
/// and presents the list of items to the client to allow the client to download the files.
/// @{

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>

/// Enable (1) or disable (0) server debugging.
#define DEBUG 0

/// An array of c-strings to store the names of the files that can be downloaded
char MediaItems[100][256];
/// The number of files that can be downloaded
int numMediaItems = 0;
/// Controls the execution of the server thread
int SERVER_RUN;


/// This struct is passed as an argument to the server thread to allow multiple arguments to be passed.
struct server_args
{
    /// The SSL reception buffer
    BIO *acpt;
    /// The SSL object pointer
    BIO *abio;
};


/// This struct is passed as an argument to newly created client threads to allow multiple arguments to be passed.
struct client_args
{
    /// The SSL object pointer
    BIO *abio;
    /// The current thread number
    int thread_number;
};


/// The main function sets up all the SSL functions, Certificates and starts the server.
/// \param argc The number of arguments passed to the function.
/// \param argv The values of the passed arguments as c-strings.
/// \return Successful or failed execution.
int main(int argc, char *argv[]);


/// This function is created as a new thread and handles all client requests.
/// \param ptr The server_args struct is passed as a void pointer.
/// \return Successful or failed execution.
void *server_thread(void *ptr);


/// This function is created as a new thread for every client that makes a request to the server.
/// \param ptr The client_args struct is passed as a void pointer.
/// \return Successful or failed execution.
void *new_client_connection(void *ptr);


/// When the current clients array is full, create a new one with double the size.
/// \param old_clients The previous array of clients.
/// \param current_size The previous size of the clients array.
/// \return A pointer to the new clients array.
pthread_t *double_size(pthread_t *old_clients, int current_size);


/// Write an arbitrary file to the client.
/// \param bio A pointer to the client's SSL object.
/// \param page The file to be written.
/// \param filename The name of the file to be written.
/// \return Successful or failed execution.
int write_page(BIO *bio, const char *page, const char *filename);


/// Read all the contents of the Media_files folder for use later in GET requests.
/// \return Successful or failed execution.
int read_media();


/// Convert between an integer and a c-string.
/// \param result The c-string to be used for the output.
/// \param number The number to be converted
/// \return The same c-string used for the output.
char *itoa(char *result, int number);

/// @}
#endif //EHN_PRAC1_SERVER_H
