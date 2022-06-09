/*		SERVER -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

#include "data_struct.h"

using namespace std;

/* TEST ONLY */
unsigned char key[] = "password12345678password12345678";
/*	END*/


int main(){

    int listner_socket, new_socket, ret, option = 1, k, fdmax;
    //uint16_t lmsg;
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
			int ct_len, aad_len, msg_len, cmd;
			unsigned char *rcv_msg, *plaintext, *ciphertext, *ct_len_byte, *aad_len_byte, *aad, *tag, *iv;


			//	READ PAYLOAD_LEN
			rcv_msg = (unsigned char*)malloc(sizeof(int));
			if(!rcv_msg)
				error_handler("malloc() [rcv_msg] failed");
			if((ret = read_byte(k, (void*)rcv_msg, sizeof(int))) < 0)
				error_handler("recv() [rcv_msg] failed");
			if(ret == 0)
				error_handler("nothing to read! 1");
			memcpy(&msg_len, rcv_msg, sizeof(int));

			//	READ AAD_LEN & AAD
			aad_len_byte = (unsigned char*)malloc(sizeof(int));
			if(!aad_len_byte)
				error_handler("malloc() [aad_len_byte] failed");
			if((ret = read_byte(k, (void*)aad_len_byte, sizeof(int))) < 0)
				error_handler("recv() [aad_len_byte] failed");
			if(ret == 0)
				error_handler("nothing to read! 2");
			memcpy(&aad_len, aad_len_byte, sizeof(int));
			aad = (unsigned char*)malloc(aad_len);
			if(!aad)
				error_handler("malloc() [aad] failed");
			if((ret = read_byte(k, (void*)aad, aad_len)) < 0)
				error_handler("recv() [aad] failed");
			if(ret == 0)
				error_handler("nothing to read! 3");
			cmd = int(aad[0]) - OFFSET;			
			
			//	READ CT_LEN & CIPHERTEXT
			ct_len_byte = (unsigned char*)malloc(sizeof(int));
			if(!ct_len_byte)
				error_handler("malloc() [ct_len_byte] failed");
			if((ret = read_byte(k, (void*)ct_len_byte, sizeof(int))) < 0)
				error_handler("recv() [ct_len_byte] failed");
			if(ret == 0)
				error_handler("nothing to read! 4");
			memcpy(&ct_len, ct_len_byte, sizeof(int));

			ciphertext = (unsigned char*)malloc(ct_len);
			if(!ciphertext)
				error_handler("malloc() [cyphertext] failed");
			if((ret = read_byte(k, (void*)ciphertext, ct_len)) < 0)
				error_handler("recv() [ciphertext] failed");
			if(ret == 0)
				error_handler("nothing to read! 5");

			//	READ TAG
			tag = (unsigned char*)malloc(TAG_LEN);
			if(!tag)
				error_handler("malloc() [tag] failed");
			if((ret = read_byte(k, (void*)tag, TAG_LEN)) < 0)
				error_handler("recv() [tag] failed");
			if(ret == 0)
				error_handler("nothing to read! 6");

			//	READ IV
			iv = (unsigned char*)malloc(IV_LEN);
			if(!iv)
				error_handler("malloc() [iv] failed");
			if((ret = read_byte(k, (void*)iv, IV_LEN)) < 0)
				error_handler("recv() [iv] failed");
			if(ret == 0)
				error_handler("nothing to read! 7");

			//	DECRYPT CT
			plaintext = (unsigned char*)malloc(ct_len + 1);
			if(!plaintext)
				error_handler("malloc() [plaintext] failed");
			gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, key, iv, IV_LEN, plaintext);

			//cout << "Messaggio ricevuto correttamente " << plaintext << endl;
			
			switch(cmd){
				case 2:{	// ls 
					DIR *dir;
					struct dirent *en;
					unsigned char *buf, *name_tmp/*, *ciphertext*/;
					int dim = 0, count = 0, num_file = 0;

					num_file = get_num_file("franca");
					dir = opendir("franca");
					if(dir){
						while((en = readdir(dir)) != NULL){
							if(!strcmp(en->d_name, ".") || !strcmp(en->d_name, ".."))
								continue;
					
							//	calculate dim for buffer
         						cout << en->d_name << endl;
							dim += strlen(en->d_name); 
							dim++;
						}
						closedir(dir);
					}
					else
						error_handler("directory not found");
					
					dir = opendir("franca");
					if(dir){
						buf = (unsigned char*)malloc(dim+1);
						while((en = readdir(dir)) != NULL){
							if(!strcmp(en->d_name, ".") || !strcmp(en->d_name, ".."))
								continue;
							
							//	copy file names into buf
							name_tmp = (unsigned char*)malloc(strlen(en->d_name) + 2);
         						name_tmp = (unsigned char*)strncpy((char*)name_tmp, en->d_name, strlen(en->d_name));
							//cout << "name tmp1: " << name_tmp << endl;
							if(num_file > 1)
								name_tmp = (unsigned char*)strncat((char*)name_tmp, "|", sizeof(char));
							//cout << "name tmp2: " << name_tmp << endl;
							if(count == 0)
								buf = (unsigned char*)strncpy((char*)buf, (char*)name_tmp, strlen((char*)name_tmp) + 1);
							else
								buf = (unsigned char*)strncat((char*)buf, (char*)name_tmp, (strlen((char*)name_tmp) + 1));

							count++;
							num_file--;
						}
						closedir(dir);
						cout << "Buf: " << buf << endl;
					}
					else
						error_handler("directory not found");
					break;
				}
				case 3:{	// up
				
					break;
				}
				case 4:{	// dl

					break;
				}
				case 5:{	// mv
				
					break;
				}
				case 6:{	// rn

					break;
				}
				case 7:{	// logout
			
					break;
				}
				default:{
					error_handler("command not found!");
					break;
				}
			}
			return 0;

                }
            }
        }
    }
    return 0;   //Unreachable code
}
