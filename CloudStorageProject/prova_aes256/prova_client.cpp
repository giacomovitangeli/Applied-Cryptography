/*		CLIENT -- PROJECT CLOUD -- APPLIED CRIPTOGRAPHY		*/

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
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>

/*	COMMAND MACRO */
#define UPLOAD 		0b001
#define DOWNLOAD 	0b010
#define DELETE		0b011
#define LIST		0b100
#define RENAME		0b101
#define LOGOUT		0b110
/*	special auth command at startup */
#define AUTH		0b111
/*	END	*/

/*	SIZE LMIT	*/
#define MAX_FILE_NAME 	24
#define MAX_FILSE_SIZE	2^^32
/*	END*/

using namespace std;

/*			DATA STRUCTURES C/S 
*/

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

/* TEST ONLY */
struct dummy_packet {
	unsigned char ciphertext[1024];
	unsigned char tag[16];
};
/*	END	*/

/*			UTILITY FUNCTIONS
*/

void error_handler(const string err){
	cout << "Errore: " << err << endl;
	exit(0);
}	

int gcm_encrypt(unsigned char *plain, int plain_len, 
				unsigned char *aad, int aad_len, 
				unsigned char *key, 
				unsigned char *iv, int iv_len, 
				unsigned char *cipher, 
				unsigned char *tag){
	
	EVP_CIPHER_CTX *ctx;
	int cipher_len, len;
	
	// CREAZIONE CONTESTO
	if(!(ctx = EVP_CIPHER_CTX_new()))
		error_handler("creazione contesto fallita");

	// INIZIALIZZAZIONE CONTESTO
	if(1 != EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv))
		error_handler("inizializzazione contesto fallita");

	// UPDATE CONTESTO -- AAD data -> quello che voglio autenticare
	if(aad && aad_len > 0){
		if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
			error_handler("update contesto (AAD) fallito");
	}

	// UPDATE CONTESTO -- Generazione ciphertext
	if(1 != EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len))
		error_handler("creazione contesto (ciphertext) fallito");
	cipher_len = len;
	
	// FINALIZE
	if(1 != EVP_EncryptFinal(ctx, cipher + len, &len))
		error_handler("final contesto fallita");
	cipher_len += len;

	//TAG check & RET
	if(aad && aad_len > 0){
		if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
			error_handler("autenticazione dati fallita");
	}

	EVP_CIPHER_CTX_free(ctx);
	return cipher_len;
}

int gcm_decrypt(unsigned char *cipher, int cipher_len, 
				unsigned char *aad, int aad_len, 
				unsigned char *tag, 
				unsigned char *key, 
				unsigned char *iv, int iv_len, 
				unsigned char *plain){

	EVP_CIPHER_CTX *ctx;
	int plain_len, len, ret;

	// CREAZIONE CONTESTO
	if(!(ctx = EVP_CIPHER_CTX_new()))
		error_handler("creazione contesto fallita");

	// INIZIALIZZAZIONE CONTESTO
	if(1 != EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, iv))
		error_handler("inizializzazione contesto fallita");

	// UPDATE CONTESTO -- AAD data -> quello che voglio autenticare
	if(aad && aad_len > 0){
		if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
			error_handler("update contesto (AAD) fallito");
	}

	// UPDATE CONTESTO -- Generazione ciphertext
	if(1 != EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len))
		error_handler("creazione contesto (ciphertext) fallito");
	plain_len = len;

	//TAG check
	if(aad && aad_len > 0){
		if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
			error_handler("autenticazione dati fallita");
	}

	// FINALIZE
	ret = EVP_DecryptFinal(ctx, plain + len, &len);
	EVP_CIPHER_CTX_cleanup(ctx);
	
	if(ret > 0){
		plain_len += len;
		return plain_len;
	}
	else{
		error_handler("verifica fallita");
		return -1;
	}
}

//#include "header.cpp"

/* TEST ONLY */
unsigned char key[] = "password12345678password12345678";
unsigned char iv[] = "123456789012";
/*	END*/

int main(){

	int socket_d, len, ret;
	unsigned char *rcv_msg, *resp_msg, *cipher, tag[16], *plaintext, *ciphertext;
	uint16_t lmsg;
	struct sockaddr_in sv_addr;
	struct dummy_packet packet;

	/*	Cleanup and initialization	 */
	memset(&sv_addr, 0, sizeof(sv_addr)); 
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_port = htons(4242); //RANDOM port number
	if((ret = inet_pton(AF_INET, "127.0.0.1", &(sv_addr.sin_addr))) == 0)
		error_handler("address format not valid");

	if((socket_d = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		error_handler("socket creation failed");

	cout << "> Socket creato correttamente!" << endl; 

	if((ret = connect(socket_d, (struct sockaddr*)&sv_addr, sizeof(sv_addr))) < 0)
		error_handler("connect() failed");

	/* Endless loop - Managing entire session */

	while(1){
		plaintext = (unsigned char*)malloc(1024);
		ciphertext = (unsigned char*)malloc(1024);
		cout << "Enter a message.." << endl;
		cin >> plaintext;

		ret = strlen((char*)plaintext);
		len = gcm_encrypt(plaintext, ret, iv, 12, key, iv, 12, packet.ciphertext, packet.tag);

		lmsg = htons(len);
		if((ret = send(socket_d, (void*)&lmsg, sizeof(uint16_t), 0)) < 0)
			error_handler("send() [lmsg] failed");

		if((ret = send(socket_d, (void*)packet.ciphertext, len, 0)) < 0)
			error_handler("send() [ciphertext] failed");

		if((ret = send(socket_d, (void*)packet.tag, 16, 0)) < 0)
			error_handler("send() [tag] failed");

		memset(plaintext, 0, 1024);
		memset(ciphertext, 0, 1024);
		memset(tag, 0, 16);

		if((ret = recv(socket_d, (void*)&lmsg, sizeof(uint16_t), 0)) < 0)
			error_handler("recv() [lmsg] failed");

		if((ret = recv(socket_d, (void*)ciphertext, len, 0)) < 0)
			error_handler("recv() [ciphertext] failed");

		if((ret = recv(socket_d, (void*)tag, 16, 0)) < 0)
			error_handler("recv() [tag] failed");

		gcm_decrypt(ciphertext, len, iv, 12, tag, key, iv, 12, plaintext);
		cout << plaintext << endl;
	}
	return 0; // inutile
}