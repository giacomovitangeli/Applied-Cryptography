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

	int listner_socket = 0, new_socket = 0, ret = 0, option = 1, k = 0, fdmax;
	unsigned char *resp_msg, *rcv_msg, *tag, *plaintext, *ciphertext;
	uint16_t lmsg;
	struct sockaddr_in my_addr, client_addr;
	fd_set master; 
	fd_set read_set;
	socklen_t len = 0;

	FD_ZERO(&master);
	FD_ZERO(&read_set);

	listner_socket = socket(AF_INET, SOCK_STREAM, 0); // Creazione listner
	setsockopt(listner_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));	//permette di riusare il solito indirizzo per il socket, necessario per provare senza dover spengere la virtual machine
	if(listner_socket < 0){
		cout << "Errore nella creazione del socket di comunicazione!" << endl;
		exit(0);
	}

	cout << ">>> Socket creato correttamente!" << endl;

	/*	Pulizia e inizializzazione strutture server	 */
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(4242); //4242 porta CASUALE
	my_addr.sin_addr.s_addr = INADDR_ANY; // vincola il socket a tutte le interfacce, usare inet_addr("127.0.0.1"); se si vuole utilizzare il solo indirizzo locale

	ret = bind(listner_socket, (struct sockaddr*)&my_addr, sizeof(my_addr));
	if(ret < 0){
		cout << "Errore nella bind()" << endl;
		exit(0);
	}
	    
	ret = listen(listner_socket, 10); // 10 = numero massimo di connessioni in attesa, l'11esima verrà rifiutata -- 10 numero CASUALE
	if(ret < 0){
		cout << "Errore nella listen()" << endl;
		exit(0);
	}

	cout << ">>> Socket associato correttamente all'indirizzo!" << endl;
	FD_SET(listner_socket, &master);	// Aggiungo il listner al master
	fdmax = listner_socket;
	len = sizeof(client_addr);

	while(1){	//Processo unico, client multipli gestiti tramite select()
		read_set = master;
		select(fdmax + 1, &read_set, NULL, NULL, NULL);
		for(k = 0; k <= fdmax; k++){
			if(FD_ISSET(k, &read_set)){
				if(k == listner_socket){ // Sono il listner
					cout << ">>> In attesa di connessione..." << endl;
        			new_socket = accept(listner_socket, (struct sockaddr*)&client_addr, &len);
       				if(new_socket < 0){
            				cout << "Errore nella creazione del socket di comunicazione!" << endl;
            				exit(0);
        			}
					FD_SET(new_socket, &master);
					if(new_socket > fdmax)
						fdmax = new_socket;
				}
				else{	// Non sono il listner
					cout << ">>> In attesa di un comando dal client..." << endl;
					/* Alloco spazio per i messaggi sia in entrata che in uscita */
					rcv_msg = (unsigned char*)malloc(128);
					if(!rcv_msg)
						exit(0);
					resp_msg = (unsigned char*)malloc(128);
					if(!resp_msg)
						exit(0);
					plaintext = (unsigned char*)malloc(128);
					ciphertext = (unsigned char*)malloc(128);
					tag = (unsigned char*)malloc(16);
					/* RICEVO LA LUNGHEZZA DEL MESSAGGIO */
					ret = recv(k, (void*)&lmsg, sizeof(uint16_t), 0);
					if(ret == 0){
						cout << "Comunicazione col client interrotta!" << endl;
						exit(0);
					}
					if(ret < 0){
		                cout << "Errore nella recv!" << endl;
		                exit(0);
		            }

					/* RICEVO IL MESSAGGIO */
					len = ntohs(lmsg);
					ret = recv(k, (void*)rcv_msg, len, 0);
					if(ret == 0){
						cout << "Comunicazione col client interrotta!" << endl;
						exit(0);
					}
					if(ret < 0){
						cout << "Errore nella recv!" << endl;
						exit(0);
					}
					
					gcm_decrypt(rcv_msg, len, NULL, NULL, tag, key, iv, 12, plaintext);
					cout << plaintext << endl;
					//fgets(resp_msg, 128, stdin);
					len = strlen((char*)rcv_msg);
					lmsg = htons(len);
					send(k, (void*)&lmsg, sizeof(uint16_t), 0);
					send(k, (void*)rcv_msg, len, 0);
					
					memset(rcv_msg, 0, 128);
					memset(resp_msg, 0, 128);
				}
			}
		}
	}				
	return 0; // inutile
}


