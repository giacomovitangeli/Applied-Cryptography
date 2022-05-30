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

