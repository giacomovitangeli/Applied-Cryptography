#include <openssl/rand.h>
#include <iostream>
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

using namespace std;

unsigned char key[] = "password";
unsigned char iv[] = "123456789012";

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
	cout << endl << "contesto creato" << endl;
	// INIZIALIZZAZIONE CONTESTO
	if(1 != EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv))
		error_handler("inizializzazione contesto fallita");
	cout << "contesto inizializzato" << endl;
	// UPDATE CONTESTO -- AAD data -> quello che voglio autenticare
	if(aad && aad_len > 0){
		if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
			error_handler("update contesto (AAD) fallito");
	}
	cout << "after aad block" << endl;
	// UPDATE CONTESTO -- Generazione ciphertext
	if(1 != EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len))
		error_handler("creazione contesto (ciphertext) fallito");

	cipher_len = len;
	cout << "ciphertext generato" << endl;
	// FINALIZE
	if(1 != EVP_EncryptFinal(ctx, cipher + len, &len))
		error_handler("final contesto fallita");
	
	cipher_len += len;
	cout << "finalize completa" << endl;
	//TAG check & RET
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
		error_handler("autenticazione dati fallita");
	
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
	/*if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
		error_handler("autenticazione dati fallita");*/
	
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

int main(){
	
	int socket1 = 0, len = 0, ret = 0;
	unsigned char *rcv_msg, *resp_msg, *cipher, *tag, *plaintext, *ciphertext;
	uint16_t lmsg;
	struct sockaddr_in sv_addr;
	
	/*	Pulizia e inizializzazione strutture client	 */
	memset(&sv_addr, 0, sizeof(sv_addr)); 
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_port = htons(4242); //htons(atoi(4242));
	if((ret = inet_pton(AF_INET, "127.0.0.1", &(sv_addr.sin_addr))) == 0){
		cout << "Formato indirizzo non valido!" << endl;
		exit(0);
	}

	socket1 = socket(AF_INET, SOCK_STREAM, 0);
	if(socket1 < 0){
		cout << "Errore nellacreazione del socket di connessione!" << endl;
	    exit(0);
	}

	cout << ">>> Socket creato correttamente!" << endl; 
	ret = connect(socket1, (struct sockaddr*)&sv_addr, sizeof(sv_addr));
	if(ret < 0){
	    cout << "Errore di connessione!" << endl;
	    exit(0);
	}
	
	while(1){
		resp_msg = (unsigned char*)malloc(128);
		if(!resp_msg){
			cout << "Malloc failed!" << endl;
			exit(0);
		}
		rcv_msg = (unsigned char*)malloc(128);
		if(!rcv_msg){
			cout << "Malloc failed!" << endl;
			exit(0);
		}
		ciphertext = (unsigned char*)malloc(128);
		plaintext = (unsigned char*)malloc(128);
		tag = (unsigned char*)malloc(16);
		cout << "In attesa di un comando..." << endl;
		cin >> resp_msg;
		ret = strlen((char*)resp_msg);
		cout << resp_msg << ret << endl; 
		len = gcm_encrypt(resp_msg, ret, NULL, NULL, key, iv, 12, ciphertext, tag);
		cout << endl << "after encrypt" << endl;
		lmsg = htons(len);
		ret = send(socket1, (void*)&lmsg, sizeof(uint16_t), 0);
		if(ret < 0){
			cout << "Errore nella send di lmsg!" << endl;
			exit(0);
		}
		ret = send(socket1, (void*)ciphertext, len, 0);
		
		if(ret < 0){
			cout << "Errore nella send del buffer!" << endl;
			exit(0);
		}
		
		ret = recv(socket1, (void*)&lmsg, sizeof(uint16_t), 0);
		if(ret == 0){
			cout << ">>> Connessione col server persa!" << endl;
			close(socket1);
			exit(0);
		}

		if(ret < 0){
			cout << "Errore nella ricezione della risposta (dim) dal server (1)!" << endl;
			exit(0);
		}

		len = ntohs(lmsg);
		rcv_msg = (unsigned char*)malloc(len);

		if(!rcv_msg){
			cout << "Malloc failed!" << endl;
			exit(0);
		}

		ret = recv(socket1, (void*)rcv_msg, len, 0);
		if(ret < 0){
			cout << "Errore nella ricezione della risposta (buf) dal server(1)!" << endl;
			exit(0);
		}
		
		gcm_decrypt(rcv_msg, len, NULL, NULL, tag, key, iv, 12, plaintext);
		cout << plaintext << endl;
	}
	return 0; // inutile
}



