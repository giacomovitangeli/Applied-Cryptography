#ifndef CLOUDSTORAGEPROJECT_DATA_STRUCT_H
#define CLOUDSTORAGEPROJECT_DATA_STRUCT_H

/*		DATA STRUCTURES -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

//#include "util_fun.cpp"
#include <stdio.h>
#include <cstdlib>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <iostream>
#include <string>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


#define PORT 4242

//  START MACRO COMMANDS
#define UPLOAD 		0b001
#define DOWNLOAD 	0b010
#define DELETE		0b011
#define LIST		0b100
#define RENAME		0b101
#define LOGOUT		0b110
/*	special auth command at startup */
#define AUTH		0b111
//  END MACRO COMMANDS

//  START SIZE LMIT
#define MAX_FILE_NAME 	24
#define MAX_FILSE_SIZE	2^^32
//  END SIZE LIMIT

using namespace std;

/*
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
*/


// TEST ONLY
struct dummy_packet {
    unsigned char ciphertext[1024];
    unsigned char tag[16];
};


//	START CRYPTO UTILITY FUNCTIONS DECLARATIONS
void error_handler(const string);
int gcm_encrypt(unsigned char *, int ,
                unsigned char *, int ,
                unsigned char *,
                unsigned char *, int ,
                unsigned char *,
                unsigned char *);
int gcm_decrypt(unsigned char *, int ,
                unsigned char *, int ,
                unsigned char *,
                unsigned char *,
                unsigned char *, int,
                unsigned char *);
//	END CRYPTO UTILITY FUNCTIONS DECLARATIONS


//	START UTILITY FUNCTIONS
void print_man();
void check_cmd(unsigned char*, int*);
//	END UTILITY FUNCTIONS



#endif //CLOUDSTORAGEPROJECT_DATA_STRUCT_H
