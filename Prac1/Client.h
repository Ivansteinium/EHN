#ifndef EHN_PRAC1_CLIENT_H
#define EHN_PRAC1_CLIENT_H


#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <unistd.h>
#include <string.h>

/// The maximum length of a request (characters).
#define MAX_REQ_LEN 255
/// Enable (1) or disable (0) client debugging.
#define DEBUG 0

/// Sets up the client SSL connection, connects to the server and then displays or downloads requested files from the server
/// \param argc The number of arguments passes to the function.
/// \param argv The values of the passes arguments as c-strings.
/// \return Successful or failed execution.
int main(int argc, char * argv[]);

/// Clears a buffer up to a specified length.
/// \param buffer The buffer to be cleared.
/// \param length The length up to which the buffer must be cleared.
void clear_buffer(char * buffer, int length);


#endif //EHN_PRAC1_CLIENT_H
