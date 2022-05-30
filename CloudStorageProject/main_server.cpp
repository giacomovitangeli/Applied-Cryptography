/*		SERVER -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

#include "data_struct.h"



using namespace std;


//	START CRYPTO UTILITY FUNCTIONS
/*
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
*/

/* TEST ONLY */
unsigned char key[] = "password12345678password12345678";
unsigned char iv[] = "123456789012";
/*	END*/


int main(){

    int listner_socket, new_socket, ret, option = 1, k, fdmax;
    unsigned char *resp_msg, *rcv_msg, tag[16], *plaintext, *ciphertext;
    uint16_t lmsg;
    struct sockaddr_in my_addr, client_addr;

    fd_set master;
    fd_set read_set;

    socklen_t len = 0;

    FD_ZERO(&master);
    FD_ZERO(&read_set);

    if((listner_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) // Creazione listner
        error_handler("socket creation failed");

    /* VIRTUAL MACHINE TEST ONLY */
    setsockopt(listner_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));	//permette di riusare il solito indirizzo per il socket, necessario per provare senza dover spengere la virtual machine
    /*	END	*/

    cout << "> Socket created successfully!" << endl;

    /*	Clean up and initialization	 */
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(4242); //RANDOM port number
    my_addr.sin_addr.s_addr = INADDR_ANY; // C & S in same net

    if((ret = bind(listner_socket, (struct sockaddr*)&my_addr, sizeof(my_addr))) < 0)
        error_handler("bind() failed");

    cout << "> Socket binded successfully!" << endl;

    if((ret = listen(listner_socket, 10)) < 0) //RANDOM max tail constraint
        error_handler("listen() failed");

    cout << "> Socket listening..." << endl;

    FD_SET(listner_socket, &master);
    fdmax = listner_socket;
    len = sizeof(client_addr);

    /*	Endless loop - Managing client(s) request(s) - Single process with multiple descriptors */

    while(1){
        read_set = master;
        select(fdmax + 1, &read_set, NULL, NULL, NULL);
        for(k = 0; k <= fdmax; k++){ // Scan for ready socket
            if(FD_ISSET(k, &read_set)){
                if(k == listner_socket){ // Listner Socket - New connection request
                    if((new_socket = accept(listner_socket, (struct sockaddr*)&client_addr, reinterpret_cast<socklen_t *>(&len))) < 0)
                        error_handler("bind() failed");

                    FD_SET(new_socket, &master);
                    if(new_socket > fdmax)
                        fdmax = new_socket;
                }
                else{ // Serving client request

                    /* Setting envirorment */
                    if(!(plaintext = (unsigned char*)malloc(1024)))
                        error_handler("malloc() [plaintext] failed");

                    if(!(ciphertext = (unsigned char*)malloc(1024)))
                        error_handler("malloc() [ciphertext] failed");

                    /* RICEVO LUNGHEZZA DEL MESSAGGIO+MESSAGGIO+TAG */
                    if((ret = recv(k, (void*)&lmsg, sizeof(uint16_t), 0)) < 0)
                        error_handler("recv() [lmsg] failed");

                    len = ntohs(lmsg);

                    if((ret = recv(k, (void*)ciphertext, len, 0)) < 0)
                        error_handler("recv() [ciphertext] failed");

                    if((ret = recv(k, (void*)tag, 16, 0)) < 0)
                        error_handler("recv() [tag] failed");

                    gcm_decrypt(ciphertext, len, iv, 12, tag, key, iv, 12, plaintext);
                    cout << plaintext << endl;

                    memset(ciphertext, 0, 1024);
                    memset(tag, 0, 16);

                    ret = strlen((char*)plaintext);
                    len = gcm_encrypt(plaintext, ret, iv, 12, key, iv, 12, ciphertext, tag);

                    lmsg = htons(len);
                    if((ret = send(k, (void*)&lmsg, sizeof(uint16_t), 0)) < 0)
                        error_handler("send() [lmsg] failed");

                    if((ret = send(k, (void*)ciphertext, len, 0)) < 0)
                        error_handler("send() [ciphertext] failed");

                    if((ret = send(k, (void*)tag, 16, 0)) < 0)
                        error_handler("send() [tag] failed");

                    memset(plaintext, 0, 1024);
                }
            }
        }
    }
    return 0;   //Unreachable code
}
