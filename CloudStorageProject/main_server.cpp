/*		SERVER -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

#include "data_struct.h"

using namespace std;

/* TEST ONLY */
unsigned char key[] = "password12345678password12345678";
//unsigned char iv[] = "123456789012";
/*	END*/


int main(){

    int listner_socket, new_socket, ret, option = 1, k, fdmax;
    uint16_t lmsg;
    struct sockaddr_in my_addr, client_addr;

    fd_set master;
    fd_set read_set;

    socklen_t len = 0;

    FD_ZERO(&master);
    FD_ZERO(&read_set);

    if((listner_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        error_handler("socket creation failed");

    // VIRTUAL MACHINE TEST ONLY 
    setsockopt(listner_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));	//permette di riusare il solito indirizzo per il socket, necessario per provare senza dover spengere la virtual machine
    //	END	

    cout << "> Socket created successfully!" << endl;

    //	Clean up and initialization	 
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

    //	Endless loop - Managing client(s) request(s) - Single process with multiple descriptors 

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
			int ct_len, aad_len, msg_len;
			unsigned char *rcv_msg, *plaintext, *ciphertext, *ct_len_byte, *aad_len_byte, *aad, *tag, *iv;


			//	READ PAYLOAD_LEN
			rcv_msg = (unsigned char*)malloc(sizeof(int));
			if(!rcv_msg)
				error_handler("malloc() [rcv_msg] failed");
			if((ret = read_byte(k, (void*)rcv_msg, sizeof(int))) < 0)
				error_handler("recv() [rcv_msg] failed");
			if(ret == 0)
				error_handler("nothing to read!");
			memcpy(&msg_len, rcv_msg, sizeof(int));

			//	READ AAD_LEN & AAD
			aad_len_byte = (unsigned char*)malloc(sizeof(int));
			if(!aad_len_byte)
				error_handler("malloc() [aad_len_byte] failed");
			if((ret = read_byte(k, (void*)aad_len_byte, sizeof(int))) < 0)
				error_handler("recv() [aad_len_byte] failed");
			if(ret == 0)
				error_handler("nothing to read!");
			memcpy(&aad_len, aad_len_byte, sizeof(int));

			aad = (unsigned char*)malloc(aad_len);
			if(!aad)
				error_handler("malloc() [aad] failed");
			if((ret = read_byte(k, (void*)aad, aad_len)) < 0)
				error_handler("recv() [aad] failed");
			if(ret == 0)
				error_handler("nothing to read!");

			//	READ CT_LEN & CIPHERTEXT
			ct_len_byte = (unsigned char*)malloc(sizeof(int));
			if(!ct_len_byte)
				error_handler("malloc() [ct_len_byte] failed");
			if((ret = read_byte(k, (void*)ct_len_byte, sizeof(int))) < 0)
				error_handler("recv() [ct_len_byte] failed");
			if(ret == 0)
				error_handler("nothing to read!");
			memcpy(&ct_len, ct_len_byte, sizeof(int));

			ciphertext = (unsigned char*)malloc(ct_len);
			if(!ciphertext)
				error_handler("malloc() [cyphertext] failed");
			if((ret = read_byte(k, (void*)ciphertext, ct_len)) < 0)
				error_handler("recv() [ciphertext] failed");
			if(ret == 0)
				error_handler("nothing to read!");

			//	READ TAG
			tag = (unsigned char*)malloc(TAG_LEN);
			if(!tag)
				error_handler("malloc() [tag] failed");
			if((ret = read_byte(k, (void*)tag, TAG_LEN)) < 0)
				error_handler("recv() [tag] failed");
			if(ret == 0)
				error_handler("nothing to read!");

			//	READ IV
			iv = (unsigned char*)malloc(IV_LEN);
			if(!iv)
				error_handler("malloc() [iv] failed");
			if((ret = read_byte(k, (void*)iv, IV_LEN)) < 0)
				error_handler("recv() [iv] failed");
			if(ret == 0)
				error_handler("nothing to read!");

			//	DECRYPT CT
			plaintext = (unsigned char*)malloc(ct_len + 1);
			if(!plaintext)
				error_handler("malloc() [plaintext] failed");
			gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, key, iv, IV_LEN, plaintext);
			

			cout << "Messaggio ricevuto correttamente " << plaintext << endl;
			return 0;




/*
                    // Setting envirorment 
                    if(!(plaintext = (unsigned char*)malloc(1024)))
                        error_handler("malloc() [plaintext] failed");

                    if(!(ciphertext = (unsigned char*)malloc(1024)))
                        error_handler("malloc() [ciphertext] failed");

                    
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
*/
                }
            }
        }
    }
    return 0;   //Unreachable code
}
