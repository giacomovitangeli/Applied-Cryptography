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
#include <iomanip>
#include <fstream>

#define PORT 4242

//  START MACRO COMMANDS
#define MAN		1
#define LIST		2
#define UPLOAD 		3
#define DOWNLOAD 	4
#define DELETE		5
#define RENAME		6
#define LOGOUT		7
/*	special auth command at startup */
#define AUTH		10
//  END MACRO COMMANDS

//  START SIZE LMIT
#define MAX_FILE_NAME 	24
#define MAX_FILSE_SIZE	2^^32
//  END SIZE LIMIT

#define TAG_LEN		16
#define	IV_LEN		12
#define NONCE_LEN	16
#define DUMMY_BYTE	'x'

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
int check_cmd(char*);
int get_cmd(char*);
void serialize_int(int, unsigned char*);
int read_byte(int, void*, ssize_t);
//	END UTILITY FUNCTIONS



#endif //CLOUDSTORAGEPROJECT_DATA_STRUCT_H
