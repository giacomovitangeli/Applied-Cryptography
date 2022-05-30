/*		DATA STRUCTURES -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

#include <string>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>


//  START SIZE LIMIT
#define MAX_FILE_NAME 	24
#define MAX_FILSE_SIZE	2^^32
//  END SIZE LIMIT


//  START DATA STRUCTURES

struct aad_data {
    uint8_t		flag : 1;
    uint8_t		op_code : 3;
    uint8_t 	nonce;	//Suggested at least 96 bit !!
    uint32_t	file_size_avail;
    uint32_t	file_size_req;
};

struct secure_data {
    unsigned char 	file_name[MAX_FILE_NAME];
    unsigned char	file_data[1024];
    uint8_t 		file_name_size;
    char			dummy;
};

struct packet {
    uint16_t			payload_len;
    uint16_t			cipher_data_len;
    struct aad_data		aad;
    struct secure_data 	cript_data;
    unsigned char 		tag[16];
    unsigned char		iv[12];
};

//  END DATA STRUCTURES


// TEST ONLY
struct dummy_packet {
    unsigned char ciphertext[1024];
    unsigned char tag[16];
};