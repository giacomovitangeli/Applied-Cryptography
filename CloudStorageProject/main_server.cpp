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

    if((listner_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        error_handler("socket creation failed");
	exit(0);
    }
    // VIRTUAL MACHINE TEST ONLY 
    setsockopt(listner_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));	//permette di riusare il solito indirizzo per il socket, necessario per provare senza dover spengere la virtual machine
    //	END	

    cout << "> Socket created successfully!" << endl;

    //	Clean up and initialization	 
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(4242); //RANDOM port number
    my_addr.sin_addr.s_addr = INADDR_ANY; // C & S in same net

    if((ret = bind(listner_socket, (struct sockaddr*)&my_addr, sizeof(my_addr))) < 0){
        error_handler("bind() failed");
	exit(0);
    }

    cout << "> Socket binded successfully!" << endl;

    if((ret = listen(listner_socket, 10)) < 0){ //RANDOM max tail constraint
        error_handler("listen() failed");
	exit(0);
    }

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
                    if((new_socket = accept(listner_socket, (struct sockaddr*)&client_addr, reinterpret_cast<socklen_t *>(&len))) < 0){
                        error_handler("accept() failed");
			exit(0);
		    }
                    FD_SET(new_socket, &master);
                    if(new_socket > fdmax)
                        fdmax = new_socket;
                }
                else{ // Serving client request
			int ct_len, aad_len, msg_len, cmd, index_free_buf = 0;
			unsigned char *rcv_msg, *plaintext, *ciphertext, *ct_len_byte, *aad_len_byte, *aad, *tag, *iv, *free_buf[20];			
			const char *dirname = "franca";

			cout << "Perforing operation..." << endl;
			//	READ PAYLOAD_LEN
			rcv_msg = (unsigned char*)malloc(sizeof(int));
			if(!rcv_msg){
				error_handler("malloc() [rcv_msg] failed, closing socket");
				close(k);
				exit(0);
			}
			free_buf[index_free_buf] = rcv_msg;
			index_free_buf++;
			if((ret = read_byte(k, (void*)rcv_msg, sizeof(int))) < 0){
				error_handler("recv() [rcv_msg] failed, closing socket");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			if(ret == 0){
				error_handler("nothing to read! Client disconnected...");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			memcpy(&msg_len, rcv_msg, sizeof(int));

			//	READ AAD_LEN & AAD
			aad_len_byte = (unsigned char*)malloc(sizeof(int));
			if(!aad_len_byte){
				error_handler("malloc() [aad_len_byte] failed, closing socket");	// release memory of previous malloc()
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			free_buf[index_free_buf] = aad_len_byte;
			index_free_buf++;
			if((ret = read_byte(k, (void*)aad_len_byte, sizeof(int))) < 0){
				error_handler("recv() [aad_len_byte] failed, closing socket");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			if(ret == 0){
				error_handler("nothing to read! Client disconnected...");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			memcpy(&aad_len, aad_len_byte, sizeof(int));
			aad = (unsigned char*)malloc(aad_len);
			if(!aad){
				error_handler("malloc() [aad] failed, closing socket");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			free_buf[index_free_buf] = aad;
			index_free_buf++;
			if((ret = read_byte(k, (void*)aad, aad_len)) < 0){
				error_handler("recv() [aad] failed");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			if(ret == 0){
				error_handler("nothing to read! Client disconnected...");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			cmd = int(aad[0]) - OFFSET;			

			//	READ CT_LEN & CIPHERTEXT
			ct_len_byte = (unsigned char*)malloc(sizeof(int));
			if(!ct_len_byte){
				error_handler("malloc() [ct_len_byte] failed");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			free_buf[index_free_buf] = ct_len_byte;
			index_free_buf++;
			if((ret = read_byte(k, (void*)ct_len_byte, sizeof(int))) < 0){
				error_handler("recv() [ct_len_byte] failed");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			if(ret == 0){
				error_handler("nothing to read! 4");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			memcpy(&ct_len, ct_len_byte, sizeof(int));

			ciphertext = (unsigned char*)malloc(ct_len);
			if(!ciphertext){
				error_handler("malloc() [cyphertext] failed");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			free_buf[index_free_buf] = ciphertext;
			index_free_buf++;
			if((ret = read_byte(k, (void*)ciphertext, ct_len)) < 0){
				error_handler("recv() [ciphertext] failed");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			if(ret == 0){
				error_handler("nothing to read! 5");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}

			//	READ TAG
			tag = (unsigned char*)malloc(TAG_LEN);
			if(!tag){
				error_handler("malloc() [tag] failed");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			free_buf[index_free_buf] = tag;
			index_free_buf++;
			if((ret = read_byte(k, (void*)tag, TAG_LEN)) < 0){
				error_handler("recv() [tag] failed");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			if(ret == 0){
				error_handler("nothing to read! 6");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}

			//	READ IV
			iv = (unsigned char*)malloc(IV_LEN);
			if(!iv){
				error_handler("malloc() [iv] failed");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			free_buf[index_free_buf] = iv;
			index_free_buf++;
			if((ret = read_byte(k, (void*)iv, IV_LEN)) < 0){
				error_handler("recv() [iv] failed");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			if(ret == 0){
				error_handler("nothing to read! 7");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}

			//	DECRYPT CT
			plaintext = (unsigned char*)malloc(ct_len + 1);
			if(!plaintext){
				error_handler("malloc() [plaintext] failed");
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			free_buf[index_free_buf] = plaintext;
			index_free_buf++;
			ret = gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, key, iv, IV_LEN, plaintext);
			if(ret < 0){
				close(k);
				free_var(index_free_buf, free_buf);
				exit(0);
			}
			// todo: check nonce and path traversing

			// DECLARING VARIABLES
			unsigned char *resp_msg_op, *opcode_op, *nonce_op, *ciphertext_op, *plaintext_op, *ct_len_byte_op, *aad_len_byte_op, *aad_op, *tag_op, *iv_op, *payload_len_byte_op;
			int ct_len_op, aad_len_op, msg_len_op, rc_op, payload_len_op;
			
			// END

			switch(cmd){
				case 2:{	// ls 	[payload_len][aad_len]{[opcode][nonce]}[cyph_len][file_name][tag][iv]
					DIR *dir;
					struct dirent *en;
					unsigned char *buf, *name_tmp;
					int dim = 0, count = 0, num_file = 0;

					num_file = get_num_file(dirname);
					dir = opendir(dirname);
					if(dir){
						while((en = readdir(dir)) != NULL){
							if(!strcmp(en->d_name, ".") || !strcmp(en->d_name, ".."))
								continue;
					
							//	calculate dim for buffer
							dim += strlen(en->d_name); 
							dim++;
						}
						closedir(dir);
					}
					else{
						error_handler("directory not found");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					
					dir = opendir(dirname);
					if(dir){
						buf = (unsigned char*)malloc(dim+1);
						while((en = readdir(dir)) != NULL){
							if(!strcmp(en->d_name, ".") || !strcmp(en->d_name, ".."))
								continue;
							
							//	copy file names into buf
							name_tmp = (unsigned char*)malloc(strlen(en->d_name) + 2);
         						name_tmp = (unsigned char*)strncpy((char*)name_tmp, en->d_name, strlen(en->d_name));
							if(num_file > 1)
								name_tmp = (unsigned char*)strncat((char*)name_tmp, "|", sizeof(char));
							if(count == 0)
								buf = (unsigned char*)strncpy((char*)buf, (char*)name_tmp, strlen((char*)name_tmp) + 1);
							else
								buf = (unsigned char*)strncat((char*)buf, (char*)name_tmp, (strlen((char*)name_tmp) + 1));

							count++;
							num_file--;
						}
						closedir(dir);
						free(name_tmp);
					}
					else{
						error_handler("directory not found");
						
						close(k);
						free_var(index_free_buf, free_buf);

						free(name_tmp);
						free(buf);
						exit(0);
					}
					
					//	MALLOC & RAND VARIABLES
					nonce_op = (unsigned char*)malloc(NONCE_LEN);
					if(!nonce_op){
						error_handler("malloc() [nonce] failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					free_buf[index_free_buf] = nonce_op;
					index_free_buf++;
					rc_op = RAND_bytes(nonce_op, NONCE_LEN);
					if(rc_op != 1){
						error_handler("nonce generation failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}

					iv_op = (unsigned char*)malloc(IV_LEN);
					if(!iv_op){
						error_handler("malloc() [iv] failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					free_buf[index_free_buf] = iv_op;
					index_free_buf++;
					rc_op = RAND_bytes(iv, IV_LEN);
					if(rc_op != 1){
						error_handler("iv generation failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}

					tag_op = (unsigned char*)malloc(TAG_LEN);
					if(!tag_op){
						error_handler("malloc() [tag] failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					free_buf[index_free_buf] = tag_op;
					index_free_buf++;
					opcode_op = (unsigned char*)malloc(1);
					if(!opcode_op){
						error_handler("malloc() [opcode] failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					free_buf[index_free_buf] = opcode_op;
					index_free_buf++;
					opcode_op[0] = '2';

					plaintext_op = (unsigned char*)malloc(strlen((char*)buf)); 
					if(!plaintext_op){
						error_handler("malloc() [plaintext_op] failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					free_buf[index_free_buf] = plaintext_op;
					index_free_buf++;
					ciphertext_op = (unsigned char*)malloc(strlen((char*)buf));
					if(!ciphertext_op){
						error_handler("malloc() [ciphertext_op] failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					free_buf[index_free_buf] = ciphertext_op;
					index_free_buf++;
					//	SERIALIZATION

					//	AAD SERIALIZATION
					aad_len_op = 1 + NONCE_LEN;	//opcode + lunghezza nonce -- opcode = unsigned char
					aad_op = (unsigned char*)malloc(aad_len_op);
					if(!aad_op){
						error_handler("malloc() [aad_op] failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					free_buf[index_free_buf] = aad_op;
					index_free_buf++;
					aad_len_byte_op = (unsigned char*)malloc(aad_len_op);	
					if(!aad_len_byte_op){
						error_handler("malloc() [aad_len_byte_op] failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					free_buf[index_free_buf] = aad_len_byte_op;
					index_free_buf++;
					serialize_int(aad_len_op, aad_len_byte_op);
					memcpy(aad_op, opcode_op, sizeof(unsigned char));
					memcpy(&aad_op[1], nonce_op, NONCE_LEN);

					//	CIPHERTEXT LEN SERIALIZATION
					strncpy((char*)plaintext_op, (char*)buf, strlen((char*)buf));
					ct_len_op = gcm_encrypt(plaintext_op, strlen((char*)buf), aad_op, aad_len_op, key, iv_op, IV_LEN, ciphertext_op, tag_op);
					if(ct_len_op <= 0){ 
						error_handler("encrypt() failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					ct_len_byte_op = (unsigned char*)malloc(ct_len_op);
					if(!ct_len_byte_op){
						error_handler("malloc() [ct_len_byte_op] failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					free_buf[index_free_buf] = ct_len_byte_op;
					index_free_buf++;
					serialize_int(ct_len_op, ct_len_byte_op);

					//	PAYLOAD LEN SERIALIZATION
					payload_len_op = sizeof(int) + aad_len_op + sizeof(int) + ct_len_op + TAG_LEN + IV_LEN;
					payload_len_byte_op = (unsigned char*)malloc(sizeof(int));
					if(!payload_len_byte_op){
						error_handler("malloc() [payload_len_byte_op] failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					free_buf[index_free_buf] = payload_len_byte_op;
					index_free_buf++;
					serialize_int(payload_len_op, payload_len_byte_op);

					//	BUILD MESSAGE (resp_msg)
					msg_len_op = sizeof(int) + sizeof(int) + aad_len_op + sizeof(int) + ct_len_op + TAG_LEN + IV_LEN;
					resp_msg_op = (unsigned char*)malloc(msg_len_op);
					if(!resp_msg_op){
						error_handler("malloc() [resp_msg_op] failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}
					free_buf[index_free_buf] = resp_msg_op;

					memcpy(resp_msg_op, payload_len_byte_op, sizeof(int));
					memcpy((unsigned char*)&resp_msg_op[sizeof(int)], aad_len_byte_op, sizeof(int));
					memcpy((unsigned char*)&resp_msg_op[sizeof(int) + sizeof(int)], aad_op, aad_len_op);
					memcpy((unsigned char*)&resp_msg_op[sizeof(int) + sizeof(int) + aad_len_op], ct_len_byte_op, sizeof(int));
					memcpy((unsigned char*)&resp_msg_op[sizeof(int) + sizeof(int) + aad_len_op + sizeof(int)], ciphertext_op, ct_len_op);
					memcpy((unsigned char*)&resp_msg_op[sizeof(int) + sizeof(int) + aad_len_op + sizeof(int) + ct_len_op], tag_op, TAG_LEN);
					memcpy((unsigned char*)&resp_msg_op[sizeof(int) + sizeof(int) + aad_len_op + sizeof(int) + ct_len_op + TAG_LEN], iv_op, IV_LEN);

					//	SEND PACKET
					if((ret = send(k, (void*)resp_msg_op, msg_len_op, 0)) < 0){
			    			error_handler("send() failed");
						close(k);
						free_var(index_free_buf, free_buf);
						exit(0);
					}

					//	FREE MEMORY ALLOCATED (INSIDE SWITCH)
					
					free(nonce_op);
					free(opcode_op);
					free(plaintext_op);
					free(iv_op);
					free(tag_op);
					free(ciphertext_op);
					free(aad_op);
					free(aad_len_byte_op);
					free(ct_len_byte_op);
					free(payload_len_byte_op);
					free(resp_msg_op);
					free(buf);
					index_free_buf = 0;
					break;
				}
				case 3:{	// up 1:	[payload_len][aad_len]{[opcode][nonce]}[cyph_len][file_name][tag][iv]
				
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
			//	FREE MEMORY ALLOCATED (OUTSIDE SWITCH)
			free(iv);
			free(tag);
			free(plaintext);
			free(ciphertext);
			free(aad);
			free(aad_len_byte);
			free(ct_len_byte);
			free(rcv_msg);
                }
            }
        }
    }
    return 0;   //Unreachable code
}
