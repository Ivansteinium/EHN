#ifndef EHN_PRAC2_AES_H
#define EHN_PRAC2_AES_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#define MAX_REQ_LEN 12800 // pfft daar is baie memory

// AES constants
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
#define CFB8 1 // Default
#define CFB64 8
#define CFB128 16


const int S_BOX[2][16][16] = {{{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, // Forward
                               {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
                               {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
                               {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
                               {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
                               {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
                               {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
                               {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
                               {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
                               {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
                               {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
                               {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
                               {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
                               {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
                               {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
                               {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}}, // Inverse
                              {{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
                               {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
                               {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
                               {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
                               {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
                               {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
                               {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
                               {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
                               {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
                               {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
                               {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
                               {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
                               {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
                               {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
                               {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
                               {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}}};

const int PRIME_MATRIX[2][4][4] = {{{2, 3, 1, 1}, // Forward
                                    {1, 2, 3, 1},
                                    {1, 1, 2, 3},
                                    {3, 1, 1, 2}},
                                   {{14, 11, 13,  9}, // Inverse
                                    { 9, 14, 11, 13},
                                    {13,  9, 14, 11},
                                    {11, 13,  9, 14}}};


// TODO: update once done
/**
 * The main function.
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
void hex_blockify(int message[16], int current_block[4][4]);


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


/**
 * Print a c-string up to a certain length.
 * @param message The message to be printed.
 * @param message_len The length of the message.
 * @param hex Output as hexadecimal rather than ASCII if true.
 */
void print_c_string(unsigned char message[], int message_len, bool hex);


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
 * Finite field multiplication according to AES specifications.
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


#endif //EHN_PRAC2_AES_H
