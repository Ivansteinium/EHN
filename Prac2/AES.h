#ifndef EHN_PRAC2_AES_H
#define EHN_PRAC2_AES_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/timeb.h>

/// The maximum length of an input to be handled.
#define MAX_REQ_LEN 104857600 // 100 MiB = 104857600 Bytes
/// Activate or deactivate verbose mode capabilities
#define VERBOSE 1

// Constants
#define AES128 0
#define AES192 1
#define AES256 2
#define AES128_ROUNDS 10
#define AES192_ROUNDS 12
#define AES256_ROUNDS 14
#define AES128_KEY_SIZE 176
#define AES192_KEY_SIZE 208
#define AES256_KEY_SIZE 240
#define AES128_USER_KEY_SIZE 16
#define AES192_USER_KEY_SIZE 24
#define AES256_USER_KEY_SIZE 32
#define AES128_EXPANSION 10
#define AES192_EXPANSION 8
#define AES256_EXPANSION 7
#define AES128_SUB_EXPANSION 3
#define AES192_SUB_EXPANSION 5
#define AES256_SUB_EXPANSION 7
#define CFB8 1
#define CFB64 8
#define CFB128 16 // Default


/// Provides a one-to-one mapping for the non-linear substitution of a byte.
const int S_BOX[2][16][16] = {{{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76}, // Forward
                               {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
                               {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
                               {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
                               {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
                               {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
                               {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
                               {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
                               {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
                               {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
                               {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                               {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
                               {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
                               {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
                               {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
                               {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}},
                              {{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB}, // Inverse
                               {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
                               {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
                               {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
                               {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
                               {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
                               {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
                               {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
                               {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
                               {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
                               {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
                               {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
                               {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
                               {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
                               {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
                               {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}}};

/// Used for the transformation of a column in the mix columns operation.
const int PRIME_MATRIX[2][4][4] = {{{2, 3, 1, 1}, // Forward
                                    {1, 2, 3, 1},
                                    {1, 1, 2, 3},
                                    {3, 1, 1, 2}},
                                   {{14, 11, 13,  9}, // Inverse
                                    { 9, 14, 11, 13},
                                    {13,  9, 14, 11},
                                    {11, 13,  9, 14}}};


/**
 * The main function. Arguments as described in the README is passed to this function.
 * This function then uses the arguments to either encrypt or decrypt some input.
 * @param argc The number of arguments passed.
 * @param argv The arguments as C-strings.
 * @return Successful execution.
 */
int main(int argc, char *argv[]);


/**
 * Convert a char array to 4x4 block of hex.
 * @param message A c-string containing the message to be converted.
 * @param current_block The output as a 4x4 integer array.
 * @param start_pos The position from which to start the conversion in the string.
 */
void char_blockify(unsigned char message[], int current_block[4][4], int start_pos);


/**
 * Convert an integer array to 4x4 block of hex.
 * @param message An integer array containing the values to be converted.
 * @param current_block The output as a 4x4 integer array.
 */
void int_blockify(int message[16], int current_block[4][4]);


/**
 * Output a word to the terminal.
 * @param word The word to be printed.
 * @param length The length of the word.
 */
void print_word(int word[], int length);


/**
 * Output a 4x4 block to the terminal as a block of hex.
 * @param current_block The block to be printed.
 */
void print_block(int current_block[4][4]);


/**
 * Output the expanded key in rows of 16.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param expanded_key The expanded key to print.
 */
void print_expanded_key(int width, int expanded_key[]);


// Print a c-string up to a certain length in hex
void print_hex_string(unsigned char hex_string[], int message_len);


 // Write a message to a file
void write_to_file(char filename[], unsigned char message[], int message_len);


// Create the output directory and return the full file path
char *create_path(int method, char *file_name);

/**
 * Convert block back to c-string.
 * @param message The output array, must exist before being passed in.
 * @param current_block The block to be converted.
 * @param start_pos The position to start converting in the output.
 */
void char_unblockify(unsigned char message[], int current_block[4][4], int start_pos);


/**
 * Shift last items in an array to the front or vice-versa.
 * @param word The array to be rotated, also the output.
 * @param length The length of the word.
 * @param rotations The number of rotations to perform.
 * @param inverse Rotate in the opposite direction if true.
 */
void AES_word_rotate(int word[], int length, int rotations, bool inverse);


/**
 * Divide value up into its MSB and LSB Nibble and return the s_box value.
 * @param input The value to be transformed.
 * @param inverse Perform the inverse transform if true.
 * @return The transformed value.
 */
int AES_s_box_transform(int input, bool inverse);


/**
 * Core key operation, transform of previous 4 bytes.
 * @param word The bytes to be transformed, also the output.
 * @param rcon The round constant to be used.
 */
void AES_key_scheduler(int word[4], int rcon);


/**
 * Exponentiation of 2, double the previous value except when 0x80 and max value of 0xFF.
 * @param previous The value to be used exponentiated.
 * @return The exponentiated value.
 */
int AES_exp_2(int previous);


/**
 * Main key expansion function.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param expanded_key The expanded key output, the correct length array (AESxxx_KEY_SIZE + 32) must exist and be passed in here.
 * Allocate more space since AES_key_expansion deliberately writes out of bounds.
 * @param user_key The user key to be expanded.
 */
void AES_key_expansion(int width, int expanded_key[], int user_key[]);


/**
 * Substitute a block through the S-transform.
 * @param current_block The block to be transformed, also the output.
 * @param inverse Perform the inverse transform if true.
 */
void AES_sub_bytes(int current_block[4][4], bool inverse);


/**
 * The AES row shifting function.
 * @param current_block The block to be shifted, also the output.
 * @param inverse Perform the inverse shift if true.
 */
void AES_shift_rows(int current_block[4][4], bool inverse);


/**
 * Finite field multiplication.
 * @param a The first value.
 * @param b The second value.
 * @return The result of the dot product.
 */
int AES_dot_product(int a, int b);


/**
 * Perform the dot product of the block and the prime matrix.
 * @param current_block The block to be used in the dot product, also the output.
 * @param inverse Perform the inverse dot product if true.
 */
void AES_mix_cols(int current_block[4][4], bool inverse);


/**
 * XOR a block with the expanded key at a certain index
 * @param current_block The block to which the round key should be added, also the output.
 * @param expanded_key The expanded key to use.
 * @param key_index The index in the key to start from.
 */
void AES_add_round_key(int current_block[4][4], int expanded_key[], int key_index);


/**
 * The AES encryption algorithm.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param current_block The block to be encrypted, also the output.
 * @param expanded_key The expanded key to be used.
 * @return Successful execution.
 */
bool AES_encrypt(int width, int current_block[4][4], int expanded_key[]);


/**
 * The AES decryption algorithm.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param current_block The block to be decrypted, also the output.
 * @param expanded_key The expanded key to be used.
 * @return Successful execution.
 */
bool AES_decrypt(int width, int current_block[4][4], int expanded_key[]);


/**
 * The Cipher Block Chaining encryption algorithm.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param message The message to be encrypted, also the output.
 * @param message_len The length of the message.
 * @param IV The initialization vector to be used.
 * @param user_key The user key to be used.
 * @return Successful execution.
 */
bool CBC_encrypt(int width, unsigned char message[], int message_len, int IV[16], int user_key[]);


/**
 * The Cipher Block Chaining decryption algorithm.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param message The message to be decrypted, also the output.
 * @param message_len The length of the message.
 * @param IV The initialization vector to be used.
 * @param user_key The user key to be used.
 * @return Successful execution.
 */
bool CBC_decrypt(int width, unsigned char message[], int message_len, int IV[16], int user_key[]);


/**
 * The Cipher Feedback encryption algorithm.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param message The stream to be encrypted, also the output.
 * @param message_len The length of the message.
 * @param CFB_len The length of the chain to use.
 * @param IV The initialization vector to be used.
 * @param user_key The user key to be used.
 * @return Successful execution.
 */
bool CFB_encrypt(int width, unsigned char message[], int message_len, int CFB_len, int IV[16], int user_key[]);


/**
 * The Cipher Feedback decryption algorithm.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param message The stream to be decrypted, also the output.
 * @param message_len The length of the message.
 * @param CFB_len The length of the chain to use.
 * @param IV The initialization vector to be used.
 * @param user_key The user key to be used.
 * @return Successful execution.
 */
bool CFB_decrypt(int width, unsigned char message[], int message_len, int CF_Blen, int IV[16], int user_key[]);


#if VERBOSE
/**
 * The verbose version of the AES encryption algorithm. Prints out intermediate results in the encryption
 * process.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param current_block The block to be encrypted, also the output.
 * @param expanded_key The expanded key to be used.
 * @return Successful execution.
 */
bool AES_encrypt_verbose(int width, int current_block[4][4], int expanded_key[]);

/**
 * The verbose version of the AES decryption algorithm. Prints out intermediate results in the decryption
 * process.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param current_block The block to be decrypted, also the output.
 * @param expanded_key The expanded key to be used.
 * @return Successful execution.
 */
bool AES_decrypt_verbose(int width, int current_block[4][4], int expanded_key[]);

/**
 * The verbose version of the Cipher Block Chaining encryption algorithm. Prints out intermediate results in
 * the encryption process.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param message The message to be encrypted, also the output.
 * @param message_len The length of the message.
 * @param IV The initialization vector to be used.
 * @param user_key The user key to be used.
 * @return Successful execution.
 */
bool CBC_encrypt_verbose(int width, unsigned char message[], int message_len, int IV[16], int user_key[]);

/**
 * The verbose version of the Cipher Block Chaining decryption algorithm. Prints out intermediate results
 * in the decryption process.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param message The message to be decrypted, also the output.
 * @param message_len The length of the message.
 * @param IV The initialization vector to be used.
 * @param user_key The user key to be used.
 * @return Successful execution.
 */
bool CBC_decrypt_verbose(int width, unsigned char message[], int message_len, int IV[16], int user_key[]);

/**
 * The verbose version of the Cipher Feedback encryption algorithm. Prints out intermediate results in the encryption
 * process.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param message The stream to be encrypted, also the output.
 * @param message_len The length of the message.
 * @param CFB_len The length of the chain to use.
 * @param IV The initialization vector to be used.
 * @param user_key The user key to be used.
 * @return Successful execution.
 */
bool CFB_encrypt_verbose(int width, unsigned char message[], int message_len, int CFB_len, int IV[16], int user_key[]);

/**
 * The verbose version of the Cipher Feedback decryption algorithm. Prints out intermediate results in the decryption
 * process.
 * @param width Use the macros AES128, AES192 or AES256 to select which width to use.
 * @param message The stream to be decrypted, also the output.
 * @param message_len The length of the message.
 * @param CFB_len The length of the chain to use.
 * @param IV The initialization vector to be used.
 * @param user_key The user key to be used.
 * @return Successful execution.
 */
bool CFB_decrypt_verbose(int width, unsigned char message[], int message_len, int CF_Blen, int IV[16], int user_key[]);
#endif


// Convert hex to int, done because the system hex converter is unreliable
int hex_convert(char hex_string[], int length);


// Print out various tests to test the functionality of the other functions
void test_functionality( );


#endif //EHN_PRAC2_AES_H
