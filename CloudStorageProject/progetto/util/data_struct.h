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
#include <sys/stat.h>
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
#include <openssl/err.h>

#define PORT 4242

//  START MACRO COMMANDS
#define MAN		1
#define LIST		2
#define UPLOAD 		3
#define DOWNLOAD 	4
#define RENAME		5
#define DELETE		6
#define LOGOUT		7
/*	special auth command at startup */
#define AUTH		10
//  END MACRO COMMANDS

//  START SIZE LMIT
#define MAX_FILE_NAME 	24
#define MAX_FILSE_SIZE	2^^32
//  END SIZE LIMIT

#define MAX_PATH	512
#define TAG_LEN		16
#define	IV_LEN		12
#define NONCE_LEN	16
#define DUMMY_BYTE	'x'
#define OFFSET		48
#define CHUNK		1048576

// CL & SV IDENTIFIER
#define CLIENT		1
#define SERVER		0
// END

using namespace std;

// TEST ONLY 
extern unsigned char key[33];
//	END

// STRUCT MANAGING MEMORY
extern unsigned char *sv_free_buf[1024];
extern int sv_index_free_buf;

extern unsigned char *cl_free_buf[1024];
extern int cl_index_free_buf;

typedef struct _user {
	int u_socket;
	char username[10];
	unsigned char *session_key;
} user;
// END STRUCT

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
int check_cmd(char*, char*, char*);
int get_cmd(char*);
void serialize_int(int, unsigned char*);
int read_byte(int, void*, ssize_t);
int get_num_file(const char*);
void free_var(int);
void memory_handler(int, int, int, unsigned char**);
void split_file(unsigned char*, unsigned char**, unsigned char**);
int c_authenticate(int, user*);
//	END UTILITY FUNCTIONS



#endif //CLOUDSTORAGEPROJECT_DATA_STRUCT_H
