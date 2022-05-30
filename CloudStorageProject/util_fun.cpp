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

void check_cmd(unsigned char* plaintext, int* cmd){

    if (strncmp((char *) plaintext, "man", 3) == 0) {
        *cmd = 1;
        return;
    } else if (strncmp((char *) plaintext, "ls", 2) == 0) {
        *cmd = 2;
        return;
    } else if (strncmp((char *) plaintext, "up", 2) == 0){
        *cmd = 3;
        //char* path = strtok((char *)plaintext, "-");
        //cout<<path<<endl;


        //cmd_to_sv = strtok(cmd_string, " ");
        //check = strtok(NULL, " \n\0");

        //fixme segmenta e stampa "up" al posto del filename
        char * pch;
        pch = strtok ((char*)plaintext," -\n\0");
        while (pch != NULL)
        {
            printf ("%s\n", (char*)plaintext);
            pch = strtok (NULL, " -\n\0");
        }

        //path = realpath(path, NULL);
        //cout<<path<<endl;
        /*
        char *realpath(const char *restrict path,
                       char *restrict resolved_path);
        */
    }else if(strncmp((char*)plaintext, "dl", 2) == 0) {
        *cmd = 4;
    }else if(strncmp((char*)plaintext, "mv", 2) == 0) {
        *cmd = 5;
    }else if(strncmp((char*)plaintext, "rm", 2) == 0) {
        *cmd = 6;
    }
}

//	END UTILITY FUNCTIONS





