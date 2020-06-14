# EHN 410 Group 12 Practical 3

This software was developed by EHN 410 group 12 and is a toolset that can be used to encrypt or decrypt with the 
RC4 and RSA algorithms implemented from first principles.


## The main features are:
  - RC4 file encryption and decryption with a key of up to 128 bits.
  - RSA public/private key pair generation for up to 4096 bits.
  - RSA text encryption and file decryption for up to 4096 bits.

These features allow for fast and secure public-key cryptography by using RSA in conjunction with RC4.
This gives the user the advantages of having a very fast encryption process and public-key cryptography, 
which are typically in conflict with each other.


## Compilation

Use the standard **gcc** compiler available on most builds of **Linux**.<br>
This toolset requires the **GMP** library to have been installed on the system before compilation can occur.
Follow the instructions provided on the [GMP] website for information on how to do this.

[GMP]: <https://gmplib.org/manual/Installing-GMP>

There are several tools included in this toolset and they have to be compiled separately.

All of these commands should be run in a terminal window in the same folder as the source files.

**The RC4 stream file encryption/decryption tool:**

    $ gcc rc4.c prac3.c -lgmp -o rc4
    
**The RSA key generation tool:**

    $ gcc rsakeygen.c prac3.c -lgmp -o rsakeygen
    
**The RSA encryption tool:**

    $ gcc rsaencrypt.c prac3.c -lgmp -o rsaencrypt
    
**The RSA decryption tool:**

    $ gcc rsadecrypt.c prac3.c -lgmp -o rsadecrypt

Compilation was tested on **Linux Ubuntu 18.04.4 LTS**.


## Usage

A command in the following format should be run in a **terminal window** in the **same folder** where the compiled executable is located:

    $ ./executable -arg1 value1 -arg2 value2...
    
The arguments provided depend on the tool which you want to use.

**The RC4 stream file encryption/decryption tool:**

    $ ./rc4 -fi <input file> -fo <output file> -key <key file>
    
Arguments:

    -fi       Specifies the path to the input file to be encrypted or decrypted.
    -fo       Specifies the path to the output file where the result will be stored.
    -key      Specifies the path to the file that contains the key to be used for the 
              operation. If this is not specified, the user will be prompted to enter
              the key manually (in ASCII).
              
<br>

**The RSA key generation tool:**

    $ ./rsakeygen -bitLen <RSA bit length> -fopub <public key output file> -fopriv <private key output file> -init <RC4 RNG seed>
 
Arguments:

    -bitLen   Specifies the number of bits to be used in the generation of the RSA
              public/private key pair (should be between 128 and 4096 inclusive).
    -fopub    Specifies the path to the file where the public key will be stored.
    -fopriv   Specifies the path to the file where the private key will be stored.
    -init     Specifies the seed to be used for the RC4 random number generator 
              used to generate the keys (in ASCII).
             
<br>
              
**The RSA encryption tool:**

    $ ./rsaencrypt -fo <encrypted output file> -fopub <public key input file> -key <RC4 key to encrypt>

Arguments:

    -fo       Specifies the path to the output file where the result will be stored.
    -fopub    Specifies the path to the file where the previously generated public key
              is stored.
    -key      Specifies the key (used by the RC4 algorithm for encryption) to be 
              encrypted (in ASCII).
       
<br>
      
**The RSA decryption tool:**

    $ ./rsadecrypt -fi <encrypted input file> -fopriv <private key input file> -fo <decrypted output file>

Arguments:

    -fi       Specifies the path to the file to be decrypted.
    -fopriv   Specifies the path to the file where the previously generated private 
              key is stored.
    -fo       Specifies the path to the output file where the key (used by the RC4 
              algorithm for decryption) will be stored.

  
#### Attention: please take special note of the following:
 
  - Remember to add <b>"double quotes"</b> to arguments if **spaces** are present in the string.<br>
If this is **not** done, only the **first word** in the string will be processed. The user is reminded that this is 
not the case for program input prompts, where any character entered will be treated as part of the password.
  - The expected input length for the **-key** argument is **16** characters for RSA encryption and RC4 if no file is specified 
  (i.e. manual entry of the key).<br>
If an ASCII string with **less** characters are given, the key will be **padded with zeroes** at the end.
If an ASCII string with **more** characters are given, the **trailing characters** will be **discarded**.


## Makefile usage

A **Makefile** is provided with the source code to allow for easy setup and demo usage.

Open a **terminal window** in the **same folder** as the Makefile to use it.

The following command will build...
 
...the RC4 encryption/decryption tool:

    $ make rc4   
    
...the RSA key generator tool:

    $ make rsakeygen

...the RSA encryption tool:

    $ make rsaencrypt
    
...the RSA decryption tool:

    $ make rsadecrypt  
    
The following command will run the demo:<br>
**Note: the key "EHN prac 3 demo" must be entered manually when prompted.**

    $ make demo

This demo is explained in the next section (Example usage).    
Afterwards, the private/public RSA key pairs, the encrypted files and final output can be found in the same folder.

To remove all the executables and generated files, the following command can be run:

    $ make clean
    

## Example usage

### Example 1: RC4 Encryption

The following command will **encrypt** a **file** called <b>"input.txt"</b> (in the same folder) using **RC4** with the key <b>"EHN prac 3 demo"</b>
and store the result in the file <b>"encrypted.enc"</b>:

    $ ./rc4 -fi "input.txt" -fo "encrypted.enc"
    
**Note: the key "EHN prac 3 demo" must be entered manually when prompted.**
    
The following output is expected:

    EHN Group 12 Practical 3
    
    Using "input.txt" as the input file
    Using "encrypted.enc" as the output file
    Please enter the key that should be used to encrypt/decrypt the input file (ASCII):  EHN prac 3 demo
    Using "EHN prac 3 demo" as the key.
    Operation took 0 ms
    
    Encryption/Decryption complete 
 
    
The file "encrypted.enc" can be found in the same folder as the executable. 
   
### Example 2: RSA Key Generation

The following command will **generate** a **public/private RSA key pair** by using **128** bits with the seed <b>"RNG seed"</b> and store the results 
in the files <b>"pubkey.txt"</b> and <b>"privkey.txt"</b>:

    $ ./rsakeygen -bitLen 128 -fopub pubkey.txt -fopriv privkey.txt -init "RNG seed"

The following output is expected:

    EHN Group 12 Practical 3
    
    128 bits will be generated
    Using "pubkey.txt" as the public key file
    Using "privkey.txt" as the private key file
    Using "RNG seed" as the RC4 RNG seed.
    
    Done
    
The files "pubkey.txt" and "privkey.txt" can be found in the same folder as the executable. 
    
### Example 3: RSA Encryption

The following command will **encrypt** the key <b>"EHN prac 3 demo"</b> using the previously generated public key and store the result in the
file <b>"cipher.key"</b>:

    $ ./rsaencrypt -fo cipher.key -fopub pubkey.txt -key "EHN prac 3 demo"

The following output is expected:

    EHN Group 12 Practical 3
    
    Using "cipher.key" as the output file
    Using "pubkey.txt" as the public RSA key file
    Using "EHN prac 3 demo" as the key
    
    Done
    
The file "cipher.key" can be found in the same folder as the executable. 

### Example 4: RSA Decryption

The following command will **decrypt** the key in the file <b>"cipher.key"</b> using the previously generated private key and store the result in
the file <b>"plain.txt"</b>:

    $ ./rsadecrypt -fi cipher.key -fopriv privkey.txt -fo plain.txt

The following output is expected:

    EHN Group 12 Practical 3
    
    Using "cipher.key" as the input file
    Using "privkey.txt" as the private RSA key file
    Using "plain.txt" as the output file
    
    Done
    
The file "plain.txt" can be found in the same folder as the executable. 
    
### Example 5: RC4 Decryption

The following command will **decrypt** the file <b>"encrypted.enc"</b> using the decrypted key in the file <b>"plain.txt"</b> and store the result in
the file <b>"output.txt"</b>:

    $ ./rc4 -fi "encrypted.enc" -fo "output.txt" -key "plain.txt"

**Note: in this example the key "EHN prac 3 demo" is already in "plain.txt". This will differ if a different key was decrypted.**


The following output is expected:

    EHN Group 12 Practical 3
    
    Using "encrypted.enc" as the input file
    Using "output.txt" as the output file
    Using "plain.txt" as the key file
    Using "EHN prac 3 demo" as the key.
    Operation took 0 ms
    
    Encryption/Decryption complete
    
The file "output.txt" can be found in the same folder as the executable. 
