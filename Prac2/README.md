# EHN 410 Group 12 Practical 2

This software was developed by EHN 410 group 12 and is a tool that can be used to encrypt or decrypt data using the 
super-secure Advanced Encryption Standard (AES) algorithm implemented from first principles.


## The main features are:
  - AES 128, AES 192 and AES 256 support.
  - Cipher Block Chaining support.
  - Cipher Feedback support for a stream of 8, 64 and 128-bits.
  - Text and file input/output support.
  - Step-by-step verbose mode.


## Compilation

Use the standard **gcc** compiler available on most builds of **Linux**.

This command should be run in a terminal window in the same folder as **AES.c** and **AES.h**:

    $ gcc AES.c -o AES

Only standard libraries are used, so no packages need to be installed separately.

Compilation was tested on **Linux Ubuntu 18.04.4 LTS**.


## Usage

A command in the following format should be run in a terminal window in the same folder where the executable is located:

    $ ./AES -arg1 value1 -arg2 value2...

The following arguments should then be given in this order:
    
    -e (encryption), or
    -d (decryption)
    
    -cbc <len> (Cipher Block Chaining, <len> either 128, 192 or 256), or
    -cfb <len> (Cipher Feedback, <len> either 128, 192 or 256)
    
    -t <text to encrypt in ASCII or text to decrypt in HEX>, or
    -fi <input file> and
    -fo <output file>
    
    -key <password in ASCII>
    
    -iv <initialization vector in ASCII>
    
    -streamlen <len> (length of the CFB stream if '-cfb' is given, either 8, 64 or 128)
    
    -h help (will show this message)
    
    -verbose (will show all steps in the AES process)

These arguments **are** required:
  - The operation (**-e** or **-d**).
  - The chaining mode (**-cbc** or **-cfb**) and the corresponding AES width.
  - The input (**-t** or **-fi**).
  - The user key (**-key**).
  
These arguments **are not** required:
  - The output file (**-fo**) (default value of "encrypted.enc" or "decrypted.txt" will be used if not specified).
  - The initialization vector (**-iv**) (will be set to all zeroes if not specified).
  - The CFB stream length (**-streamlen**) (will be set to 128-bits if not specified).
  - The help screen (**-h**).
  - The verbose mode (**-verbose**).
  
### Attention: please take special note of the following:
 
  - Remember to add <b>"double quotes"</b> to **ASCII** inputs if **spaces** are present in the string.<br>
If this is **not** done, only the **first word** in the string will be processed.
  - The expected input length for the **-key** argument is **16** characters for AES 128, **24** characters for AES 192 and **32** characters for AES256.<br>
If an ASCII string with **less** characters are given, the key will be **padded with zeroes** at the end.
If an ASCII string with **more** characters are given, the **trailing characters** will be **discarded**.    
  - The expected input length for the **-iv** argument is **16** characters.<br>
The **same** rules for the **-key** argument apply here.


## Example usage

### Example 1

The following command will **encrypt** a **file** called <b>"input.txt"</b> (in the same folder) using **AES 128** in **Cipher Block Chaining** mode:

    $ ./AES -e -cbc 128 -fi "input.txt" -fo "encrypted.enc" -key "Very strong password" -iv "Initialization vector"
    
The following output is expected:

    Encryption selected
    AES128 with CBC selected
    Plaintext file input: "input.txt"
    Key (ASCII): "Very strong pass"
    Initialization Vector (ASCII): "Initialization v"
    
    
    Encryption in process...
    
    Encrypted file output: "CBC output/encrypted.enc"
    
The file "encrypted.enc" can be found in the folder "CBC output" located in the same folder as the executable. 

If the output folder does not exist, the program will attempt to create it. 

If the program does not have sufficient permissions to create folders, the file will be found in the same folder as the executable.
    
### Example 2

The following command will **decrypt** a **file** called <b>"encrypted.jpg"</b> using **AES 192** in **Cipher Feedback** mode with a stream length of **64-bits**:

    $ ./AES -d -cfb 192 -fi "encrypted.jpg" -fo "image.jpg" -key "Very strong password" -iv "Initialization vector" -streamlen 64
    
The following output is expected:

    Decryption selected
    AES192 with CFB selected
    Encrypted file input: "encrypted.jpg"
    Key (ASCII): "Very strong password"
    Initialization Vector (ASCII): "Initialization v"
    64-bit CFB selected
    
    
    Decryption in process...
    
    Plaintext file output: "CFB output/image.jpg"

The file "image.jpg" can be found in the folder "CFB output" located in the same folder as the executable.

The same conditions mentioned in Example 1 apply here. 
      
### Example 3

The following command will **encrypt** the **ASCII** string <b>"Text to encrypt"</b> using **AES 256** in **Cipher Block Chaining** mode:

    $ ./AES -e -cbc 256 -t "Text to encrypt" -key "Very strong password" -iv "Initialization vector"
    
The following output is expected:

     Encryption selected
     AES256 with CBC selected
     Plaintext message (ASCII): "Text to encrypt"
     Key (ASCII): "Very strong password"
     Initialization Vector (ASCII): "Initialization v"
     
     
     Encryption in process...
     
     Encrypted (HEX):
     CCBD19AB3022404EFDC9804AD802936B

### Example 4

The following command will **decrypt** the **HEX** string **C7D3CAAFEE6137** using **AES 128** in **Cipher Feedback** mode with a stream length of **8-bits**:

    $ ./AES -d -cfb 128 -t C7D3CAAFEE6137 -key "Very strong password" -iv "Initialization vector" -streamlen 8

The following output is expected:

    Decryption selected
    AES128 with CFB selected
    Encrypted message (HEX): C7D3CAAFEE6137
    Key (ASCII): "Very strong pass"
    Initialization Vector (ASCII): "Initialization v"
    8-bit CFB selected
    
    
    Decryption in process...
    
    Decrypted (ASCII):
    "Success"

### Example 5

The following command will **encrypt** the **ASCII** string <b>"Test"</b> using **AES 128** in **Cipher Block Chaining** mode with **verbose output**:

    $ ./AES -e -cbc 128 -t "Verbose" -key "Very strong password" -verbose

The following output is expected:

    Encryption selected
    AES128 with CBC selected
    Plaintext message (ASCII): "Test"
    Key (ASCII): "Very strong pass"
    
    Verbose mode activated
    All steps in the AES process will now be shown
    
    The initialization vector was not set, setting to all zeroes
    
    
    Encryption in process...
    
    
    
    
    ********Block 1:********
    
    ~~~~AES encrypt input block:~~~~
    54 00 00 00 
    65 00 00 00 
    73 00 00 00 
    74 00 00 00 
    
    Add round key (initial):
    02 20 6F 70 
    00 73 6E 61 
    01 74 67 73 
    0D 72 20 73 
    
    
    ----Round 1:----
    Substitute bytes step:
    77 B7 A8 51 
    63 8F 9F EF 
    7C 92 85 8F 
    D7 40 B7 8F 
    
    Shift rows step:
    77 B7 A8 51 
    8F 9F EF 63 
    85 8F 7C 92 
    8F D7 40 B7 
    
    Mix columns step:
    6E 97 5D 22 
    69 CF A9 8D 
    63 4F 7F CF 
    96 67 F0 77 
    
    Add round key step:
    D6 0F AA A5 
    83 56 5E 1B 
    9E C6 91 52 
    BE 3D 8A 7E 
    
    
    ----Round 2:----
    Substitute bytes step:
    F6 76 AC 06 
    EC B1 58 AF 
    0B B4 81 00 
    AE 27 7E F3 
    
    Shift rows step:
    F6 76 AC 06 
    B1 58 AF EC 
    81 00 0B B4 
    F3 AE 27 7E 
    
    Mix columns step:
    4D AA 85 E9 
    E4 68 D3 7C 
    50 C7 7C 1B 
    CC 85 05 AE 
    
    Add round key step:
    67 18 C0 2B 
    50 45 09 30 
    AC B2 E7 1D 
    F3 E0 1A B8 
    
~output omitted~    
    
    ----Last round:----
    Substitute bytes step:
    AF 7B 8E 07 
    0B FB AD B3 
    FD D5 E1 E5 
    50 58 0B B1 
    
    Shift rows step:
    AF 7B 8E 07 
    FB AD B3 0B 
    E1 E5 FD D5 
    B1 50 58 0B 
    
    No mix columns step in the last round
    
    Add round key step:
    2C 4F 1C 96 
    7F 20 BF BA 
    54 A3 56 71 
    76 ED F5 6B 
    
    
    
    ********Expanded key:********
    56 65 72 79 20 73 74 72 6F 6E 67 20 70 61 73 73 
    B8 EA FD 28 98 99 89 5A F7 F7 EE 7A 87 96 9D 09 
    2A B4 FC 3F B2 2D 75 65 45 DA 9B 1F C2 4C 06 16 
    07 DB BB 1A B5 F6 CE 7F F0 2C 55 60 32 60 53 76 
    DF 36 83 39 6A C0 4D 46 9A EC 18 26 A8 8C 4B 50 
    AB 85 D0 FB C1 45 9D BD 5B A9 85 9B F3 25 CE CB 
    B4 0E CF F6 75 4B 52 4B 2E E2 D7 D0 DD C7 19 1B 
    32 DA 60 37 47 91 32 7C 69 73 E5 AC B4 B4 FC B7 
    3F 6A C9 BA 78 FB FB C6 11 88 1E 6A A5 3C E2 DD 
    CF F2 08 BC B7 09 F3 7A A6 81 ED 10 03 BD 0F CD 
    83 84 B5 C7 34 8D 46 BD 92 0C AB AD 91 B1 A4 60 
    
    Encrypted (HEX):
    2C7F54764F20A3ED1CBF56F596BA716B
