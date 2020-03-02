#ifndef EHN_PRAC1_SERVER_H
#define EHN_PRAC1_SERVER_H


#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>


#define maxMediaItems  100
#define maxMediaNameSize  256
#define DEBUG 0


char MediaItems[maxMediaItems][maxMediaNameSize];
int numMediaItems = 0;
int SERVER_RUN;


struct server_args
{   // This struct is passed as an argument to the server thread
    // to allow multiple arguments to be passed
    BIO *acpt;
    BIO *abio;
};


struct client_args
{   // This struct is passed as an argument to newly created client threads
    // to allow multiple arguments to be passed
    BIO *abio; // The SSL object pointer
    int thread_number; // The current thread number
};


/// The main function sets up all the SSL functions, Certificates and starts the server.
/// \param argc The number of arguments passes to the function.
/// \param argv The values of the passes arguments as c-strings.
/// \return Successful or failed execution.
int main(int argc, char *argv[]);


/// This function is created as a new thread and handles all client requests.
/// \param ptr The server_args struct is passes as a void pointer.
/// \return Successful or failed execution.
void *server_thread(void *ptr);


/// This function is created as a new thread for every client that makes a request to the server.
/// \param ptr The client_args struct is passes as a void pointer.
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


#endif //EHN_PRAC1_SERVER_H
