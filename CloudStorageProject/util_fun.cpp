/*		UTILITY FUNCTIONS -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

#include "data_struct.h"


using namespace std;


//	START CRYPTO UTILITY FUNCTIONS

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
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        error_handler("autenticazione dati fallita");

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

//	END CRYPTO UTILITY FUNCTIONS

//	START UTILITY FUNCTIONS
void print_man(){

    cout<<endl<<"Welcome in the cloud manual:"<<endl<<endl;
    cout<<"manual: man"<<endl;
    cout<<"list: ls"<<endl;
    cout<<"upload: up -[path/filename]"<<endl;
    cout<<"download: dl -[filename]"<<endl;
    cout<<"rename: mv -[old_filename] -[new_filename]"<<endl;
    cout<<"delete: rm -[filename]"<<endl;
    cout<<endl;
}

int check_cmd(char* plaintext){
 
    	char *ptr = strtok(plaintext, "-");
	if(strlen(ptr) > 3 || strlen(ptr) < 2)
		return -1;
	
	int command = get_cmd(ptr);
	if(command < 0)
		return -1;

	cout << command << endl;

	return command;
}

int get_cmd(char* cmd){
	if(strncmp(cmd, "man", 3) == 0)
		return 1;
	if(strncmp(cmd, "ls", 2) == 0)
		return 2;
	if(strncmp(cmd, "up", 2) == 0)
		return 3;
	if(strncmp(cmd, "dl", 2) == 0)
		return 4;
	if(strncmp(cmd, "mv", 2) == 0)
		return 5;
	if(strncmp(cmd, "rm", 2) == 0)
		return 6;
	
	return -1;
}

void serialize_int(int val, unsigned char *c){

	c[0] =  val & 0xFF;
	c[1] = (val>>8) & 0xFF;
	c[2] = (val>>16) & 0xFF;
	c[3] = (val>>24) & 0xFF;
}

int read_payload(int sock){
	int ret, p_len;
	if((ret = recv(sock, (void*)&p_len, sizeof(int), 0)) < 0)
		return -1;

	return p_len;
}
//	END UTILITY FUNCTIONS





