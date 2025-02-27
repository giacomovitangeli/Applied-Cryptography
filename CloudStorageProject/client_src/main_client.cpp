/*		CLIENT -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

#include "./../util/data_struct.h"

using namespace std;

int main(){

	int socket_d, ret, cmd, dim_f1, dim_f2;
	unsigned char *command = NULL, *command_copy = NULL, *path1 = NULL, *path2 = NULL, *file1 = NULL, *file2 = NULL;
	struct sockaddr_in sv_addr;
	user *this_user;
	char *cl_dir = NULL;

	cl_dir = (char*)malloc(MAX_PATH);
	if(!cl_dir){
		error_handler("malloc failed");
		exit(0);
	}
	getcwd(cl_dir, MAX_PATH);
	strncat(cl_dir, "/client_src/file/", strlen("/client_src/file/"));
	
	//	Cleanup and initialization	 
	memset(&sv_addr, 0, sizeof(sv_addr));
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_port = htons(4242); //RANDOM port number
	if((ret = inet_pton(AF_INET, "127.0.0.1", &(sv_addr.sin_addr))) == 0){
		error_handler("address format not valid");
		exit(0);
	}

	if((socket_d = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		error_handler("socket creation failed");
		exit(0);
	}		

	cout << "> Socket created successfully!" << endl;

	if((ret = connect(socket_d, (struct sockaddr*)&sv_addr, sizeof(sv_addr))) < 0){
		error_handler("connect() failed");
		close(socket_d);
		exit(0);
	}

	for(int i = 0; i < 1024; i++)
		cl_free_buf[i] = 0;

	print_man();

	// AUTH PHASE
	this_user = new user;
	this_user->session_key = (unsigned char*)malloc(EVP_CIPHER_key_length(EVP_aes_256_gcm()));
	if(!this_user->session_key){
		error_handler("Malloc failed");
		close(socket_d);
		free_var(CLIENT);
		exit(0);
	}
	this_user->c_counter = 0;
	this_user->s_counter = 0;
	if((ret = c_authenticate(socket_d, &this_user)) < 0){
		error_handler("authentication failed");
		close(socket_d);
		exit(0);
	}

	// Endless loop - Managing entire session 

	while(1) {
		memory_handler(CLIENT, socket_d, 128, &command);
		memory_handler(CLIENT, socket_d, 128, &command_copy);
       
		cout << "Enter a message.." << endl;
		cin.getline((char*)command, 128);
		if((char)command[0] == '\0')
			continue;

		if((cmd = get_cmd((char*)command)) < 0){
			error_handler("Command not found. Type 'man' for the Manual");
			continue;
		}

		if(cmd == 5){
			memory_handler(CLIENT, socket_d, 64, &path1);
			memory_handler(CLIENT, socket_d, 64, &path2);
			memory_handler(CLIENT, socket_d, 16, &file1);
			memory_handler(CLIENT, socket_d, 16, &file2);

			dim_f1 = split_file(command, &file1);
			cout << "Insert new filename: " << endl;

			cin.getline((char*)file2, 16);
			dim_f2 = strlen((char*)file2);

			strncpy((char*)path1, cl_dir, strlen(cl_dir));
			path1 = (unsigned char*)strncat((char*)path1, (char*)file1, strlen((char*)file1));

			if(strstr((char*)file1, "|") != NULL || strstr((char*)file2, "|") != NULL){
				error_handler("Pipe '|' is not allowed in file name");
				free_var(CLIENT);
				continue;
			}
		}
		else if(cmd == 3 || cmd == 4 || cmd == 6){
			memory_handler(CLIENT, socket_d, 64, &path1);
			memory_handler(CLIENT, socket_d, 16, &file1);
			split_file(command, &file1);
			
			if(strstr((char*)file1, "|") != NULL){
				error_handler("Pipe '|' is not allowed in file name");
				free_var(CLIENT);
				continue;
			}

			strncpy((char*)path1, cl_dir, strlen(cl_dir));
			path1 = (unsigned char*)strncat((char*)path1, (char*)file1, strlen((char*)file1));
		}

	        switch(cmd){
	        	case MAN:{	// man command
                		print_man();
				break;
			}
	        	case LIST:{	// ls command		[payload_len][aad_len]{[opcode][nonce]}[cyph_len][dummy_byte][tag][iv]
				int payload_len, ct_len, aad_len, msg_len, rc;
				unsigned int sv_counter;
    				unsigned char *rcv_msg, *resp_msg, *tag, *iv, *plaintext, *ciphertext, *opcode, *nonce, *aad, *aad_len_byte, *payload_len_byte, *ct_len_byte;	
				unsigned char flag;		
		
				//	MALLOC & RAND VARIABLES
				memory_handler(CLIENT, socket_d, NONCE_LEN, &nonce);
				memory_handler(CLIENT, socket_d, TAG_LEN, &tag);
				memory_handler(CLIENT, socket_d, 1, &opcode);
				memory_handler(CLIENT, socket_d, 1, &plaintext);
				memory_handler(CLIENT, socket_d, 1, &ciphertext);
				memory_handler(CLIENT, socket_d, IV_LEN, &iv);

				rc = RAND_bytes(iv, IV_LEN);
				if(rc != 1){
					error_handler("iv generation failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				opcode[0] = '2';
				memset(ciphertext, 0, 1);

				//	SERIALIZATION

				//	AAD SERIALIZATION
				aad_len = 1 + sizeof(unsigned int); 
				memory_handler(CLIENT, socket_d, aad_len, &aad);			
				memory_handler(CLIENT, socket_d, sizeof(int), &aad_len_byte); 
				serialize_int(aad_len, aad_len_byte);
				memcpy(aad, opcode, sizeof(unsigned char));
				memcpy(&aad[1], &this_user->c_counter, sizeof(unsigned int));
				this_user->c_counter++;

				//	CIPHERTEXT LEN SERIALIZATION
				plaintext[0] = DUMMY_BYTE;
				ct_len = gcm_encrypt(plaintext, sizeof(char), aad, aad_len, this_user->session_key, iv, IV_LEN, ciphertext, tag);
				if(ct_len <= 0){ 
					error_handler("encrypt() failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				memory_handler(CLIENT, socket_d, sizeof(int), &ct_len_byte);
				serialize_int(ct_len, ct_len_byte);

				//	PAYLOAD LEN SERIALIZATION
				payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(CLIENT, socket_d, sizeof(int), &payload_len_byte);
				serialize_int(payload_len, payload_len_byte);

				//	BUILD MESSAGE (resp_msg)
				msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(CLIENT, socket_d, msg_len, &resp_msg);

				memcpy(resp_msg, payload_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int)], aad_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int)], aad, aad_len);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int)], ciphertext, ct_len);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len], tag, TAG_LEN);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], iv, IV_LEN);
				
				//	SEND PACKET
				if((ret = send(socket_d, (void*)resp_msg, msg_len, 0)) < 0){
		    			error_handler("send() failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				cout << endl;

				//	CLEAN UP VARIABLES
				free_var(CLIENT);

				//	MALLOC & RAND VARIABLES
				memory_handler(CLIENT, socket_d, NONCE_LEN, &nonce);
				memory_handler(CLIENT, socket_d, TAG_LEN, &tag);
				memory_handler(CLIENT, socket_d, 1, &opcode);
				memory_handler(CLIENT, socket_d, IV_LEN, &iv);
				ct_len = 0;
				aad_len = 0;
				payload_len = 0;
				msg_len = 0;
				// 	END

				//	RECEIVE SERVER REPLAY

				//	READ PAYLOAD_LEN
				memory_handler(CLIENT, socket_d, sizeof(int), &rcv_msg);
				if((ret = read_byte(socket_d, (void*)rcv_msg, sizeof(int))) < 0){
					error_handler("recv() [rcv_msg] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 1");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				memcpy(&msg_len, rcv_msg, sizeof(int));

				//	READ AAD_LEN & AAD			
				memory_handler(CLIENT, socket_d, sizeof(int), &aad_len_byte);
				if((ret = read_byte(socket_d, (void*)aad_len_byte, sizeof(int))) < 0){
					error_handler("recv() [aad_len_byte] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 2");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				memcpy(&aad_len, aad_len_byte, sizeof(int));
				memory_handler(CLIENT, socket_d, aad_len, &aad);
				if((ret = read_byte(socket_d, (void*)aad, aad_len)) < 0){
					error_handler("recv() [aad] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 3");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				cmd = int(aad[0]) - OFFSET;
				memcpy(&sv_counter, &aad[1], sizeof(unsigned int));
				if(this_user->s_counter != sv_counter || sv_counter == UINT_MAX){
					error_handler("Session exiperd");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				this_user->s_counter++;		
				flag = aad[5];
				//	READ CT_LEN & CIPHERTEXT
				memory_handler(CLIENT, socket_d, sizeof(int), &ct_len_byte);
				if((ret = read_byte(socket_d, (void*)ct_len_byte, sizeof(int))) < 0){
					error_handler("recv() [ct_len_byte] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 4");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				memcpy(&ct_len, ct_len_byte, sizeof(int));

				memory_handler(CLIENT, socket_d, ct_len, &plaintext);
				memory_handler(CLIENT, socket_d, ct_len, &ciphertext);
				if((ret = read_byte(socket_d, (void*)ciphertext, ct_len)) < 0){
					error_handler("recv() [ciphertext] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 5");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				//	READ TAG
				if((ret = read_byte(socket_d, (void*)tag, TAG_LEN)) < 0){
					error_handler("recv() [tag] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 6");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				//	READ IV
				if((ret = read_byte(socket_d, (void*)iv, IV_LEN)) < 0){
					error_handler("recv() [iv] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 7");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				//	DECRYPT CT
				ret = gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, this_user->session_key, iv, IV_LEN, plaintext);
				if(ret < 0){
					error_handler("decrypt failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				if(flag == '1'){
					cout << "These are the files in your cloud folder: " << endl;
					char *token = strtok((char*)plaintext, "|");
					while(token != NULL){
						cout << token << endl;
						token = strtok(NULL, "|");
					}
				}
				else
					cout << plaintext << endl;

				free_var(CLIENT);
				break;
			}
			case UPLOAD:{	// up command 1 - request - [pay_len][aad_len]{[nonce][opcode][file_size_req]}[ciph_len]([ciphertext - file_name])[TAG][IV]
				int payload_len, ct_len, aad_len, rc, msg_len;
				unsigned int sv_counter;
				long int file_size;
	    			unsigned char *rcv_msg, *resp_msg, *tag, *iv, *plaintext, *ciphertext, *opcode, *nonce, *aad, *aad_len_byte, *payload_len_byte, *ct_len_byte, *file_size_byte;
				unsigned char flag;
				struct stat *s_buf;	

				//	MALLOC & RAND VARIABLES
				memory_handler(CLIENT, socket_d, MAX_FILE_NAME, &plaintext);
				memory_handler(CLIENT, socket_d, MAX_FILE_NAME, &ciphertext);
				memory_handler(CLIENT, socket_d, NONCE_LEN, &nonce);
				memory_handler(CLIENT, socket_d, IV_LEN, &iv);
				memory_handler(CLIENT, socket_d, TAG_LEN, &tag);
				memory_handler(CLIENT, socket_d, 1, &opcode);

				rc = RAND_bytes(iv, IV_LEN);
				if(rc != 1){
					error_handler("iv generation failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				opcode[0] = '3';
				
				//	FILE STAT
				s_buf = (struct stat*)malloc(sizeof(struct stat));
				if(!s_buf){
					error_handler("malloc() [buffer stat] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				cl_free_buf[cl_index_free_buf] = (unsigned char*)s_buf;
				cl_index_free_buf++;

				if((stat((char*)path1, s_buf)) < 0){
					error_handler("No file with this name in your folder (or stat() failed)");
					free_var(CLIENT);
					break;
				}
				file_size = s_buf->st_size;
				if(file_size > 2147483647){
					memory_handler(CLIENT, socket_d, sizeof(long int), &file_size_byte);
					serialize_longint(file_size, file_size_byte);
				}
				else{
					memory_handler(CLIENT, socket_d, sizeof(int), &file_size_byte);
					serialize_int(file_size, file_size_byte);
				}
				strncpy((char*)plaintext, (char*)file1, strlen((char*)file1));

				//	SERIALIZATION UP-1
		
				//	AAD SERIALIZATION
				if(file_size > 2147483647)
					aad_len = 1 + sizeof(unsigned int) + sizeof(long int);
				else
					aad_len = 1 + sizeof(unsigned int) + sizeof(int);
					
				memory_handler(CLIENT, socket_d, aad_len, &aad);
				memory_handler(CLIENT, socket_d, sizeof(int), &aad_len_byte);

				serialize_int(aad_len, aad_len_byte);
				memcpy(aad, opcode, sizeof(unsigned char));
				memcpy(&aad[1], &this_user->c_counter, sizeof(unsigned int));
				this_user->c_counter++;
				if(file_size > 2147483647)
					memcpy(&aad[5], &file_size, sizeof(long int));
				else
					memcpy(&aad[5], &file_size, sizeof(int));

				//	CIPHERTEXT LEN SERIALIZATION
				ct_len = gcm_encrypt(plaintext, strlen((char*)plaintext), aad, aad_len, this_user->session_key, iv, IV_LEN, ciphertext, tag);
				if(ct_len <= 0){ 
					error_handler("encrypt() failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				memory_handler(CLIENT, socket_d, sizeof(int), &ct_len_byte);
				serialize_int(ct_len, ct_len_byte);

				//	PAYLOAD LEN SERIALIZATION
				payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(CLIENT, socket_d, sizeof(int), &payload_len_byte);
				serialize_int(payload_len, payload_len_byte);

				//	BUILD MESSAGE (resp_msg)
				msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(CLIENT, socket_d, msg_len, &resp_msg);

				memcpy(resp_msg, payload_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int)], aad_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int)], aad, aad_len);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int)], ciphertext, ct_len);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len], tag, TAG_LEN);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], iv, IV_LEN);
				
				//	SEND PACKET
				if((ret = send(socket_d, (void*)resp_msg, msg_len, 0)) < 0){
		    			error_handler("send() failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				//	REQUEST ACK
				//	CLEAN UP VARIABLES
				memset(iv, 0, IV_LEN);
				memset(tag, 0, TAG_LEN);
				memset(plaintext, 0, MAX_FILE_NAME);
				memset(ciphertext, 0, MAX_FILE_NAME);
				memset(aad, 0, aad_len);
				memset(ct_len_byte, 0, sizeof(int));
				memset(aad_len_byte, 0, sizeof(int));
				memset(payload_len_byte, 0, sizeof(int));
				ct_len = 0;
				aad_len = 0;
				payload_len = 0;
				msg_len = 0;
				// 	END

				//	RECEIVE SERVER REPLAY

				//	READ PAYLOAD_LEN
				memory_handler(CLIENT, socket_d, sizeof(int), &rcv_msg);
				if((ret = read_byte(socket_d, (void*)rcv_msg, sizeof(int))) < 0){
					error_handler("recv() [rcv_msg] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 1");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				memcpy(&msg_len, rcv_msg, sizeof(int));

				//	READ AAD_LEN & AAD
				if((ret = read_byte(socket_d, (void*)aad_len_byte, sizeof(int))) < 0){
					error_handler("recv() [aad_len_byte] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 2");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				memcpy(&aad_len, aad_len_byte, sizeof(int));
				if((ret = read_byte(socket_d, (void*)aad, aad_len)) < 0){
					error_handler("recv() [aad] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 3");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}			
				memcpy(&sv_counter, &aad[1], sizeof(unsigned int));
				if(this_user->s_counter != sv_counter || sv_counter == UINT_MAX){
					error_handler("Session exiperd");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}	
				this_user->s_counter++;

				//	READ CT_LEN & CIPHERTEXT
				if((ret = read_byte(socket_d, (void*)ct_len_byte, sizeof(int))) < 0){
					error_handler("recv() [ct_len_byte] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 4");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				memcpy(&ct_len, ct_len_byte, sizeof(int));

				if((ret = read_byte(socket_d, (void*)ciphertext, ct_len)) < 0){
					error_handler("recv() [ciphertext] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 5");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				//	READ TAG
				if((ret = read_byte(socket_d, (void*)tag, TAG_LEN)) < 0){
					error_handler("recv() [tag] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 6");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				//	READ IV
				if((ret = read_byte(socket_d, (void*)iv, IV_LEN)) < 0){
					error_handler("recv() [iv] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 7");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				//	DECRYPT CT
				ret = gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, this_user->session_key, iv, IV_LEN, plaintext);
				if(ret < 0){
					error_handler("decrypt failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				flag = aad[5];
				if(flag != '1'){
					error_handler("Upload error");
					free_var(CLIENT);
					break;
				}
				cout << "Ricevuta conferma per upload" << endl;

				//	SENDING CHUNK

				// clean up variables
				memset(iv, 0, IV_LEN);
				memset(tag, 0, TAG_LEN);
				memset(nonce, 0, NONCE_LEN);
				ct_len = 0;
				aad_len = 2 + sizeof(unsigned int);
				payload_len = 0;
				msg_len = 0;
				rc = 0;

				//	FILE OPENING
				FILE *fd;
				unsigned char *data_pt, *data_ct, *data_aad, *data_aad_len_byte, *data_ct_len_byte, *data_payload_len_byte, *data_resp_msg, *data_rcv_msg, *file_buffer;

				memory_handler(CLIENT, socket_d, aad_len, &data_aad);

				fd = fopen((char*)path1, "rb");
				if(!fd){
					error_handler("file opening failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				
				long int size_res = file_size;
				if(file_size > CHUNK){
					cout << "File greater than 1Mb - Proceding to send chunks" << endl;
					for(long int i = 0; i < file_size - CHUNK && file_size > CHUNK; i += CHUNK){	// If file_size is greater than 1 chunk (1mb) then send the file divided in chunk but not the last
						data_pt = (unsigned char*)malloc(CHUNK);
						data_ct = (unsigned char*)malloc(CHUNK);
						if(!data_pt || !data_ct){
							error_handler("malloc() failed");
							free_var(CLIENT);
							close(socket_d);
							exit(0);
						}
						file_buffer = (unsigned char*)calloc(CHUNK, sizeof(unsigned char));
						if(!file_buffer){
							error_handler("malloc() failed");
							free_var(CLIENT);
							close(socket_d);
							exit(0);
						}
					
						if((fread(file_buffer, sizeof(unsigned char), CHUNK, fd)) <= 0)
							cout << "err" << endl;
						memcpy(data_pt, file_buffer, CHUNK);

						// RANDOM VALUES
						rc = RAND_bytes(tag, TAG_LEN);
						if(rc != 1){
							error_handler("nonce generation failed");
							free_var(CLIENT);
							close(socket_d);
							exit(0);
						}
						rc = RAND_bytes(iv, IV_LEN);
						if(rc != 1){
							error_handler("nonce generation failed");
							free_var(CLIENT);
							close(socket_d);
							exit(0);
						}

						// AAD INITIALIZATION
						flag = '0';
						opcode[0] = '3';

						memory_handler(CLIENT, socket_d, aad_len, &data_aad);
						memory_handler(CLIENT, socket_d, sizeof(int), &data_aad_len_byte);
						serialize_int(aad_len, data_aad_len_byte);
						memcpy(data_aad, opcode, sizeof(unsigned char));
						memcpy(&data_aad[1], &this_user->c_counter, sizeof(unsigned int));
						this_user->c_counter++;
						memcpy(&data_aad[5], &flag, sizeof(unsigned char));
						
						// CT SERIALIZATION
						ct_len = gcm_encrypt(data_pt, CHUNK, data_aad, aad_len, this_user->session_key, iv, IV_LEN, data_ct, tag);
						if(ct_len <= 0){ 
							error_handler("encrypt() failed");
							free_var(CLIENT);
							close(socket_d);
							exit(0);
						}

						memory_handler(CLIENT, socket_d, sizeof(int), &data_ct_len_byte);
						serialize_int(ct_len, data_ct_len_byte);

						// PAYLOAD SERIALIZATION
						payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;	
						memory_handler(CLIENT, socket_d, sizeof(int), &data_payload_len_byte);
						serialize_int(payload_len, data_payload_len_byte);

						//	BUILD MESSAGE (resp_msg)
						msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
						data_resp_msg = (unsigned char*)malloc(msg_len);
						memcpy(data_resp_msg, data_payload_len_byte, sizeof(int));
						memcpy((unsigned char*)&data_resp_msg[sizeof(int)], data_aad_len_byte, sizeof(int));
						memcpy((unsigned char*)&data_resp_msg[sizeof(int) + sizeof(int)], data_aad, aad_len);
						memcpy((unsigned char*)&data_resp_msg[sizeof(int) + sizeof(int) + aad_len], data_ct_len_byte, sizeof(int));
						memcpy((unsigned char*)&data_resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int)], data_ct, ct_len);
						memcpy((unsigned char*)&data_resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len], tag, TAG_LEN);
						memcpy((unsigned char*)&data_resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], iv, IV_LEN);

						//	SEND PACKET
						if((ret = send(socket_d, (void*)data_resp_msg, msg_len, 0)) < 0){
				    			error_handler("send() failed ");
							perror("send fails");
							free_var(CLIENT);
							close(socket_d);
							exit(0);
						}
						// end send
						cout << "Sent chunk #" << i/CHUNK << endl;
						free(data_pt);
						free(data_ct);
						free(file_buffer);
						free(data_resp_msg);
						size_res -= CHUNK;
						if(size_res < CHUNK)
							break;
					}
				}
				// send last chunk or the single chunk composing the file
				cout << "Proceding to send the last chunk" << endl;
				free_var(CLIENT);
				memory_handler(CLIENT, socket_d, size_res, &data_pt);
				memory_handler(CLIENT, socket_d, size_res, &data_ct);
				memory_handler(CLIENT, socket_d, aad_len, &data_aad);
				memory_handler(CLIENT, socket_d, size_res, &file_buffer);

				memcpy(data_pt, file_buffer, size_res);
	
				// RANDOM VALUES
				memory_handler(CLIENT, socket_d, NONCE_LEN, &nonce);
				memory_handler(CLIENT, socket_d, IV_LEN, &iv);
				memory_handler(CLIENT, socket_d, TAG_LEN, &tag);
				memory_handler(CLIENT, socket_d, 1, &opcode);

				rc = RAND_bytes(tag, TAG_LEN);
				if(rc != 1){
					error_handler("tag generation failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				rc = RAND_bytes(iv, IV_LEN);
				if(rc != 1){
					error_handler("iv generation failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				// AAD INITIALIZATION
				flag = '1';
				opcode[0] = '3';

				memory_handler(CLIENT, socket_d, sizeof(int), &data_aad_len_byte);
				memory_handler(CLIENT, socket_d, aad_len, &data_aad);
				serialize_int(aad_len, data_aad_len_byte);
				memcpy(data_aad, opcode, sizeof(unsigned char));
				memcpy(&data_aad[1], &this_user->c_counter, sizeof(unsigned int));
				memcpy(&data_aad[5], &flag, sizeof(unsigned char));
				this_user->c_counter++;

				// CT SERIALIZATION
				ct_len = gcm_encrypt(data_pt, size_res, data_aad, aad_len, this_user->session_key, iv, IV_LEN, data_ct, tag);
				if(ct_len <= 0){ 
					error_handler("encrypt() failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				memory_handler(CLIENT, socket_d, sizeof(int), &data_ct_len_byte);
				serialize_int(ct_len, data_ct_len_byte);

				// PAYLOAD SERIALIZATION
				payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;	
				memory_handler(CLIENT, socket_d, sizeof(int), &data_payload_len_byte);
				serialize_int(payload_len, data_payload_len_byte);

				//	BUILD MESSAGE (resp_msg)
				msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(CLIENT, socket_d, msg_len, &data_resp_msg);

				memcpy(data_resp_msg, data_payload_len_byte, sizeof(int));
				memcpy((unsigned char*)&data_resp_msg[sizeof(int)], data_aad_len_byte, sizeof(int));
				memcpy((unsigned char*)&data_resp_msg[sizeof(int) + sizeof(int)], data_aad, aad_len);
				memcpy((unsigned char*)&data_resp_msg[sizeof(int) + sizeof(int) + aad_len], data_ct_len_byte, sizeof(int));
				memcpy((unsigned char*)&data_resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int)], data_ct, ct_len);
				memcpy((unsigned char*)&data_resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len], tag, TAG_LEN);
				memcpy((unsigned char*)&data_resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], iv, IV_LEN);

				//	SEND PACKET
				if((ret = send(socket_d, (void*)data_resp_msg, msg_len, 0)) < 0){
		    			error_handler("send() failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				cout << "Sent last chunk" << endl;
				
				//	RECEIVING OK

				free_var(CLIENT);
				//	READ PAYLOAD_LEN
				memory_handler(CLIENT, socket_d, sizeof(int), &data_rcv_msg);
				if((ret = read_byte(socket_d, (void*)data_rcv_msg, sizeof(int))) < 0){
					error_handler("recv() [rcv_msg] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 1");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				memcpy(&msg_len, data_rcv_msg, sizeof(int));

				//	READ AAD_LEN & AAD
				memory_handler(CLIENT, socket_d, sizeof(int), &aad_len_byte);
				if((ret = read_byte(socket_d, (void*)aad_len_byte, sizeof(int))) < 0){
					error_handler("recv() [aad_len_byte] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 2");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				memcpy(&aad_len, aad_len_byte, sizeof(int));
				memory_handler(CLIENT, socket_d, aad_len, &aad);
				if((ret = read_byte(socket_d, (void*)aad, aad_len)) < 0){
					error_handler("recv() [aad] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 3");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				cmd = int(aad[0]) - OFFSET;
				memcpy(&sv_counter, &aad[1], sizeof(unsigned int));
				if(this_user->s_counter != sv_counter || sv_counter == UINT_MAX){
					error_handler("Session exiperd");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}	
				this_user->s_counter++;				
				flag = aad[5];
				if((int(flag) - OFFSET) == 0){
					error_handler("Upload error");
					free_var(CLIENT);
					break;
				}

				//	READ CT_LEN & CIPHERTEXT
				memory_handler(CLIENT, socket_d, sizeof(int), &ct_len_byte);
				if((ret = read_byte(socket_d, (void*)ct_len_byte, sizeof(int))) < 0){
					error_handler("recv() [ct_len_byte] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 4");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				memcpy(&ct_len, ct_len_byte, sizeof(int));
				memory_handler(CLIENT, socket_d, ct_len, &ciphertext);
				memory_handler(CLIENT, socket_d, ct_len, &plaintext);
				if((ret = read_byte(socket_d, (void*)ciphertext, ct_len)) < 0){
					error_handler("recv() [ciphertext] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 5");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				//	READ TAG
				memory_handler(CLIENT, socket_d, TAG_LEN, &tag);
				if((ret = read_byte(socket_d, (void*)tag, TAG_LEN)) < 0){
					error_handler("recv() [tag] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 6");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				//	READ IV
				memory_handler(CLIENT, socket_d, IV_LEN, &iv);
				if((ret = read_byte(socket_d, (void*)iv, IV_LEN)) < 0){
					error_handler("recv() [iv] failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 7");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				//	DECRYPT CT
				ret = gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, this_user->session_key, iv, IV_LEN, plaintext);
				if(ret < 0){
					error_handler("decrypt failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				cout << "Upload ended successfully." << endl;
				free_var(CLIENT);
				break;
			}
		    case DOWNLOAD:{	// dl command
				int payload_len, ct_len, aad_len, rc, msg_len;
				unsigned int sv_counter;
				long int file_size;
	    			unsigned char *rcv_msg, *resp_msg, *tag, *iv, *plaintext, *ciphertext, *opcode, *nonce, *aad, *aad_len_byte, *payload_len_byte, *ct_len_byte;
				unsigned char flag;

				char* fullpath = NULL;
				fullpath = (char*)calloc(MAX_PATH, sizeof(char));
				if(!fullpath){
					error_handler("malloc() failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				strncpy(fullpath, cl_dir, strlen(cl_dir));
				fullpath = strncat(fullpath, (char*)file1, strlen((char*)file1));
				if(access(fullpath, F_OK) == 0){	// File already exist
					error_handler("File already exists on this device.");
					free(fullpath);
					free_var(CLIENT);
					break;
				}
				//	MALLOC & RAND VARIABLES
				memory_handler(CLIENT, socket_d, strlen((char*)file1), &plaintext);
				memory_handler(CLIENT, socket_d, strlen((char*)file1), &ciphertext);
				memory_handler(CLIENT, socket_d, NONCE_LEN, &nonce);
				memory_handler(CLIENT, socket_d, IV_LEN, &iv);
				memory_handler(CLIENT, socket_d, TAG_LEN, &tag);
				memory_handler(CLIENT, socket_d, 1, &opcode);
				
				rc = RAND_bytes(iv, IV_LEN);
				if(rc != 1){
					error_handler("iv generation failed");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}

				opcode[0] = '4';
				memset(ciphertext, 0, strlen((char*)file1));
				strncpy((char*)plaintext, (char*)file1, strlen((char*)file1));
				
				//	SERIALIZATION DL-1
		
				//	AAD SERIALIZATION
				aad_len = 1 + sizeof(unsigned int);	
				memory_handler(CLIENT, socket_d, aad_len, &aad);
				memory_handler(CLIENT, socket_d, sizeof(int), &aad_len_byte);

				serialize_int(aad_len, aad_len_byte);
				memcpy(aad, opcode, sizeof(unsigned char));
				memcpy(&aad[1], &this_user->c_counter, sizeof(unsigned int));
				this_user->c_counter++;

				//	CIPHERTEXT LEN SERIALIZATION
				ct_len = gcm_encrypt(plaintext, strlen((char*)plaintext), aad, aad_len, this_user->session_key, iv, IV_LEN, ciphertext, tag);
				if(ct_len <= 0){ 
					error_handler("encrypt() failed");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				memory_handler(CLIENT, socket_d, sizeof(int), &ct_len_byte);
				serialize_int(ct_len, ct_len_byte);

				//	PAYLOAD LEN SERIALIZATION
				payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;	
				memory_handler(CLIENT, socket_d, sizeof(int), &payload_len_byte);
				serialize_int(payload_len, payload_len_byte);

				//	BUILD MESSAGE (resp_msg)
				msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(CLIENT, socket_d, msg_len, &resp_msg);

				memcpy(resp_msg, payload_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int)], aad_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int)], aad, aad_len);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int)], ciphertext, ct_len);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len], tag, TAG_LEN);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], iv, IV_LEN);
				
				//	SEND PACKET
				if((ret = send(socket_d, (void*)resp_msg, msg_len, 0)) < 0){
		    			error_handler("send() failed");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				
				//	CLEAN UP VARIABLES
				memset(iv, 0, IV_LEN);
				memset(tag, 0, TAG_LEN);
				memset(plaintext, 0, strlen((char*)file1));
				memset(ciphertext, 0, strlen((char*)file1));
				memset(aad, 0, aad_len);
				memset(ct_len_byte, 0, sizeof(int));
				memset(aad_len_byte, 0, sizeof(int));
				memset(payload_len_byte, 0, sizeof(int));
				ct_len = 0;
				aad_len = 0;
				payload_len = 0;
				msg_len = 0;
				// 	END

				//	RECEIVE SERVER REPLAY

				//	READ PAYLOAD_LEN
				memory_handler(CLIENT, socket_d, sizeof(int), &rcv_msg);
				if((ret = read_byte(socket_d, (void*)rcv_msg, sizeof(int))) < 0){
					error_handler("recv() [rcv_msg] failed");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 1");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				memcpy(&msg_len, rcv_msg, sizeof(int));

				//	READ AAD_LEN & AAD
				if((ret = read_byte(socket_d, (void*)aad_len_byte, sizeof(int))) < 0){
					error_handler("recv() [aad_len_byte] failed");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 2");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				memcpy(&aad_len, aad_len_byte, sizeof(int));
				if((ret = read_byte(socket_d, (void*)aad, aad_len)) < 0){
					error_handler("recv() [aad] failed");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 3");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				memcpy(&sv_counter, &aad[1], sizeof(unsigned int));
				if(this_user->s_counter != sv_counter || sv_counter == UINT_MAX){
					error_handler("Session exiperd");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}		
				this_user->s_counter++;

				//	READ CT_LEN & CIPHERTEXT
				if((ret = read_byte(socket_d, (void*)ct_len_byte, sizeof(int))) < 0){
					error_handler("recv() [ct_len_byte] failed");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 4");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				memcpy(&ct_len, ct_len_byte, sizeof(int));

				if((ret = read_byte(socket_d, (void*)ciphertext, ct_len)) < 0){
					error_handler("recv() [ciphertext] failed");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 5");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}

				//	READ TAG
				if((ret = read_byte(socket_d, (void*)tag, TAG_LEN)) < 0){
					error_handler("recv() [tag] failed");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 6");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}

				//	READ IV
				if((ret = read_byte(socket_d, (void*)iv, IV_LEN)) < 0){
					error_handler("recv() [iv] failed");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 7");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}

				//	DECRYPT CT
				ret = gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, this_user->session_key, iv, IV_LEN, plaintext);
				if(ret < 0){
					error_handler("decrypt failed");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}

				flag = aad[5];
				if(flag != '1'){
					error_handler("Download error. Aborting...");
					cout << plaintext << endl;
					free_var(CLIENT);
					free(fullpath);
					break;
				}
				memcpy(&file_size, &aad[6], sizeof(long int));	// getting file size from replay
				cout << "Download request OK. Starting..." << endl;
				free_var(CLIENT); // RESET, reallocation needed

				int chunk_num;
				long int size_res;
				if(file_size % CHUNK != 0)
					chunk_num = (file_size / CHUNK) + 1;
				else
					chunk_num = file_size / CHUNK;
				cout << "file size: " << file_size << endl << "pt: " << plaintext << endl;
				size_res = file_size;
				FILE *dl_file;
				dl_file = fopen(fullpath, "ab");
				if(!dl_file){
					error_handler("file creation failed");
					free_var(CLIENT);
					free(fullpath);
					close(socket_d);
					exit(0);
				}
				cout << "Downloaded chunk #" << 5 << " su " << chunk_num << endl;
				unsigned char *chunk_buf;
				for(int i = 0; i < chunk_num; i++){
					//	READ PAYLOAD_LEN
					memory_handler(CLIENT, socket_d, sizeof(int), &rcv_msg);
					if((ret = read_byte(socket_d, (void*)rcv_msg, sizeof(int))) < 0){
						error_handler("recv() [rcv_msg] failed");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! 1");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}
					memcpy(&msg_len, rcv_msg, sizeof(int));
					
					//	READ AAD_LEN & AAD
					memory_handler(CLIENT, socket_d, sizeof(int), &aad_len_byte);
					if((ret = read_byte(socket_d, (void*)aad_len_byte, sizeof(int))) < 0){
						error_handler("recv() [aad_len_byte] failed");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! 2");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}
					memcpy(&aad_len, aad_len_byte, sizeof(int));
					memory_handler(CLIENT, socket_d, aad_len, &aad);
					if((ret = read_byte(socket_d, (void*)aad, aad_len)) < 0){
						error_handler("recv() [aad] failed");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! 3");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}
					memcpy(&sv_counter, &aad[1], sizeof(unsigned int));
					if(this_user->s_counter != sv_counter || sv_counter == UINT_MAX){
						error_handler("Session exiperd");
						free_var(CLIENT);
						close(socket_d);
						exit(0);
					}	
					this_user->s_counter++;
					flag = aad[5];
	
					//	READ CT_LEN & CIPHERTEXT
					memory_handler(CLIENT, socket_d, sizeof(int), &ct_len_byte);
					if((ret = read_byte(socket_d, (void*)ct_len_byte, sizeof(int))) < 0){
						error_handler("recv() [ct_len_byte] failed");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! 4");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}
					memcpy(&ct_len, ct_len_byte, sizeof(int));
					memory_handler(CLIENT, socket_d, ct_len, &ciphertext);
					if((ret = read_byte(socket_d, (void*)ciphertext, ct_len)) < 0){
						error_handler("recv() [ciphertext] failed");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! 5");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}

					//	READ TAG
					memory_handler(CLIENT, socket_d, TAG_LEN, &tag);
					if((ret = read_byte(socket_d, (void*)tag, TAG_LEN)) < 0){
						error_handler("recv() [tag] failed");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! 6");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}

					//	READ IV
					memory_handler(CLIENT, socket_d, IV_LEN, &iv);
					if((ret = read_byte(socket_d, (void*)iv, IV_LEN)) < 0){
						error_handler("recv() [iv] failed");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! 7");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}

					//	DECRYPT CT
					memory_handler(CLIENT, socket_d, CHUNK, &chunk_buf);
					ret = gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, this_user->session_key, iv, IV_LEN, chunk_buf);
					if(ret < 0){
						error_handler("decrypt failed");
						free_var(CLIENT);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						close(socket_d);
						exit(0);
					}
					
					if(flag != '1' && i == chunk_num - 1){
						error_handler("Unexpected error. Waiting last chunk but flag is not '1'. Aborting operation...");
						close(socket_d);
						fclose(dl_file);
						remove(fullpath);
						free(fullpath);
						free_var(CLIENT);
						exit(0);
					}

					// WRITE BYTES TO FILE
					if(i == chunk_num - 1){ // last chunk, might be < 1MB
						if((ret = fwrite(chunk_buf, 1, size_res, dl_file)) < 0){
							close(socket_d);
							fclose(dl_file);
							remove(fullpath);
							free(fullpath);
							free_var(CLIENT);
							exit(0);
						}
					}
					else{
						if((ret = fwrite(chunk_buf, 1, CHUNK, dl_file)) < 0){
							close(socket_d);
							fclose(dl_file);
							remove(fullpath);
							free(fullpath);
							free_var(CLIENT);
							exit(0);
						}
					}
					cout << "Downloaded chunk #" << (i+1) << " su " << chunk_num << endl;
					free_var(CLIENT);
					size_res -= CHUNK;
				}
				
				cout << "Download completed!" << endl;
				free(fullpath);
				fclose(dl_file);
				free_var(CLIENT);
				break;
			}
		    case RENAME:{	// mv command
				int payload_len, ct_len, aad_len, rc, msg_len;
				unsigned int sv_counter;
				unsigned char *rcv_msg, *resp_msg, *tag, *iv, *plaintext, *ciphertext, *opcode, *nonce, *aad, *aad_len_byte, *payload_len_byte, *ct_len_byte;

				// MALLOC & RAND VARIABLES
				memory_handler(CLIENT, socket_d, 512, &plaintext);
				memory_handler(CLIENT, socket_d, NONCE_LEN, &nonce);
				memory_handler(CLIENT, socket_d, IV_LEN, &iv);
				memory_handler(CLIENT, socket_d, TAG_LEN, &tag);
				memory_handler(CLIENT, socket_d, 1, &opcode);
				memory_handler(CLIENT, socket_d, 512, &ciphertext);

				rc = RAND_bytes(iv, IV_LEN);
				if(rc != 1){
					error_handler("iv generation failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}

				opcode[0] = '5';
				char *full_command = (char*)malloc(dim_f1 + dim_f2 + 2);
				if(!full_command){
					error_handler("malloc failed");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				full_command = strncat((char*)file1, "|", strlen("|"));
				full_command = strncat((char*)full_command, (char*)file2, dim_f2);
				strncpy((char*)plaintext, (char*)full_command, strlen((char*)full_command));

				// SERIALIZATION UP-1

				// AAD SERIALIZATION
				aad_len = 1 + sizeof(unsigned int) + sizeof(int);
				memory_handler(CLIENT, socket_d, aad_len, &aad);
				memory_handler(CLIENT, socket_d, sizeof(int), &aad_len_byte);

				serialize_int(aad_len, aad_len_byte);
				memcpy(aad, opcode, sizeof(unsigned char));
				memcpy(&aad[1], &this_user->c_counter, sizeof(unsigned int));
				this_user->c_counter++;

				// CIPHERTEXT LEN SERIALIZATION
				ct_len = gcm_encrypt(plaintext, strlen((char*)plaintext), aad, aad_len, this_user->session_key, iv, IV_LEN, ciphertext, tag);
				if(ct_len <= 0){
				    error_handler("encrypt() failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				memory_handler(CLIENT, socket_d, sizeof(int), &ct_len_byte);
				serialize_int(ct_len, ct_len_byte);

				// PAYLOAD LEN SERIALIZATION
				payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(CLIENT, socket_d, sizeof(int), &payload_len_byte);
				serialize_int(payload_len, payload_len_byte);

				// BUILD MESSAGE (resp_msg)
				msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(CLIENT, socket_d, msg_len, &resp_msg);

				memcpy(resp_msg, payload_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int)], aad_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int)], aad, aad_len);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int)], ciphertext, ct_len);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len], tag, TAG_LEN);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], iv, IV_LEN);
	
				// SEND PACKET
				if((ret = send(socket_d, (void*)resp_msg, msg_len, 0)) < 0){
				    error_handler("send() failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				// CLEAN UP VARIABLES
				memset(iv, 0, IV_LEN);
				memset(tag, 0, TAG_LEN);
				memset(plaintext, 0, 512);
				memset(ciphertext, 0, 512);
				memset(aad, 0, aad_len);
				memset(ct_len_byte, 0, sizeof(int));
				memset(aad_len_byte, 0, sizeof(int));
				memset(payload_len_byte, 0, sizeof(int));
				ct_len = 0;
				aad_len = 0;
				payload_len = 0;
				msg_len = 0;
				//  END

				// RECEIVE SERVER REPLAY

				// READ PAYLOAD_LEN
				memory_handler(CLIENT, socket_d, sizeof(int), &rcv_msg);
				if((ret = read_byte(socket_d, (void*)rcv_msg, sizeof(int))) < 0){
				    error_handler("recv() [rcv_msg] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 1");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				memcpy(&msg_len, rcv_msg, sizeof(int));
				// READ AAD_LEN & AAD
				if((ret = read_byte(socket_d, (void*)aad_len_byte, sizeof(int))) < 0){
				    error_handler("recv() [aad_len_byte] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 2");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				memcpy(&aad_len, aad_len_byte, sizeof(int));
				if((ret = read_byte(socket_d, (void*)aad, aad_len)) < 0){
				    error_handler("recv() [aad] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 3");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				cmd = int(aad[0]) - OFFSET;
				memcpy(&sv_counter, &aad[1], sizeof(unsigned int));
				if(this_user->s_counter != sv_counter || sv_counter == UINT_MAX){
					error_handler("Session exiperd");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				this_user->s_counter++;
	
				// READ CT_LEN & CIPHERTEXT
				if((ret = read_byte(socket_d, (void*)ct_len_byte, sizeof(int))) < 0){
				    error_handler("recv() [ct_len_byte] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 4");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				memcpy(&ct_len, ct_len_byte, sizeof(int));

				if((ret = read_byte(socket_d, (void*)ciphertext, ct_len)) < 0){
				    error_handler("recv() [ciphertext] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 5");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				// READ TAG
				if((ret = read_byte(socket_d, (void*)tag, TAG_LEN)) < 0){
				    error_handler("recv() [tag] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 6");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				// READ IV
				if((ret = read_byte(socket_d, (void*)iv, IV_LEN)) < 0){
				    error_handler("recv() [iv] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 7");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				// DECRYPT CT
				ret = gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, this_user->session_key, iv, IV_LEN, plaintext);
				if(ret < 0){
				    error_handler("decrypt failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				if(aad[5] == '1')
					cout << "Rename complete successfully" << endl;
				else
					cout << "Something went wrong. Rename failed." << endl << plaintext << endl;

				free_var(CLIENT);
				//free(full_command);
				break;
			}
		    case DELETE:{	// rm command
				int payload_len, ct_len, aad_len, rc, msg_len;
				unsigned int sv_counter;
				unsigned char *rcv_msg, *resp_msg, *tag, *iv, *plaintext, *ciphertext, *opcode, *nonce, *aad, *aad_len_byte, *payload_len_byte, *ct_len_byte;

				//	MALLOC & RAND VARIABLES
				memory_handler(CLIENT, socket_d, 64, &plaintext);
				memory_handler(CLIENT, socket_d, NONCE_LEN, &nonce);
				memory_handler(CLIENT, socket_d, IV_LEN, &iv);
				memory_handler(CLIENT, socket_d, TAG_LEN, &tag);
				memory_handler(CLIENT, socket_d, 1, &opcode);
				memory_handler(CLIENT, socket_d, 512, &ciphertext);

				rc = RAND_bytes(nonce, NONCE_LEN);
				if(rc != 1){
				    error_handler("nonce generation failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				rc = RAND_bytes(iv, IV_LEN);
				if(rc != 1){
				    error_handler("iv generation failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				opcode[0] = '6';
				strncpy((char*)plaintext, (char*)file1, strlen((char*)file1));

				//	DELETE RM-1

				//	AAD SERIALIZATION
				aad_len = 1 + sizeof(unsigned int);
				memory_handler(CLIENT, socket_d, aad_len, &aad);
				memory_handler(CLIENT, socket_d, sizeof(int), &aad_len_byte);

				serialize_int(aad_len, aad_len_byte);
				memcpy(aad, opcode, sizeof(unsigned char));
				memcpy(&aad[1], &this_user->c_counter, sizeof(unsigned int));
				this_user->c_counter++;

				//	CIPHERTEXT LEN SERIALIZATION
				ct_len = gcm_encrypt(plaintext, strlen((char*)plaintext), aad, aad_len, this_user->session_key, iv, IV_LEN, ciphertext, tag);
				if(ct_len <= 0){
				    error_handler("encrypt() failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				memory_handler(CLIENT, socket_d, sizeof(int), &ct_len_byte);
				serialize_int(ct_len, ct_len_byte);

				//	PAYLOAD LEN SERIALIZATION
				payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(CLIENT, socket_d, sizeof(int), &payload_len_byte);
				serialize_int(payload_len, payload_len_byte);

				//	BUILD MESSAGE (resp_msg)
				msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(CLIENT, socket_d, msg_len, &resp_msg);

				memcpy(resp_msg, payload_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int)], aad_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int)], aad, aad_len);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int)], ciphertext, ct_len);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len], tag, TAG_LEN);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], iv, IV_LEN);

				//	SEND PACKET
				if((ret = send(socket_d, (void*)resp_msg, msg_len, 0)) < 0){
				    error_handler("send() failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				//	REQUEST ACK
				//	CLEAN UP VARIABLES
				memset(iv, 0, IV_LEN);
				memset(tag, 0, TAG_LEN);
				memset(plaintext, 0, 512);
				memset(ciphertext, 0, 512);
				memset(aad, 0, aad_len);
				memset(ct_len_byte, 0, sizeof(int));
				memset(aad_len_byte, 0, sizeof(int));
				memset(payload_len_byte, 0, sizeof(int));
				ct_len = 0;
				aad_len = 0;
				payload_len = 0;
				msg_len = 0;
				// 	END

				// RECEIVE SERVER REPLAY

				// READ PAYLOAD_LEN
				memory_handler(CLIENT, socket_d, sizeof(int), &rcv_msg);
				if((ret = read_byte(socket_d, (void*)rcv_msg, sizeof(int))) < 0){
				    error_handler("recv() [rcv_msg] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 1");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				memcpy(&msg_len, rcv_msg, sizeof(int));
				// READ AAD_LEN & AAD
				if((ret = read_byte(socket_d, (void*)aad_len_byte, sizeof(int))) < 0){
				    error_handler("recv() [aad_len_byte] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 2");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				memcpy(&aad_len, aad_len_byte, sizeof(int));
				if((ret = read_byte(socket_d, (void*)aad, aad_len)) < 0){
				    error_handler("recv() [aad] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 3");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				cmd = int(aad[0]) - OFFSET;
				memcpy(&sv_counter, &aad[1], sizeof(unsigned int));
				if(this_user->s_counter != sv_counter || sv_counter == UINT_MAX){
					error_handler("Session exiperd");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}
				this_user->s_counter++;
	
				// READ CT_LEN & CIPHERTEXT
				if((ret = read_byte(socket_d, (void*)ct_len_byte, sizeof(int))) < 0){
				    error_handler("recv() [ct_len_byte] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 4");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				memcpy(&ct_len, ct_len_byte, sizeof(int));

				if((ret = read_byte(socket_d, (void*)ciphertext, ct_len)) < 0){
				    error_handler("recv() [ciphertext] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 5");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				// READ TAG
				if((ret = read_byte(socket_d, (void*)tag, TAG_LEN)) < 0){
				    error_handler("recv() [tag] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 6");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				// READ IV
				if((ret = read_byte(socket_d, (void*)iv, IV_LEN)) < 0){
				    error_handler("recv() [iv] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 7");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				// DECRYPT CT
				ret = gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, this_user->session_key, iv, IV_LEN, plaintext);
				if(ret < 0){
				    error_handler("decrypt failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				if(aad[5] == '1')
					cout << "File deleted from cloud." << endl;
				else
					cout << "Something went wrong. Remove failed." << endl << plaintext << endl;

				free_var(CLIENT);
				break;
			}
			case LOGOUT:{
				int payload_len, ct_len, aad_len, rc, msg_len;
				unsigned int sv_counter;
				unsigned char *rcv_msg, *resp_msg, *tag, *iv, *plaintext, *ciphertext, *opcode, *nonce, *aad, *aad_len_byte, *payload_len_byte, *ct_len_byte;
				
				//	MALLOC & RAND VARIABLES
				memory_handler(CLIENT, socket_d, 1, &plaintext);
				memory_handler(CLIENT, socket_d, NONCE_LEN, &nonce);
				memory_handler(CLIENT, socket_d, IV_LEN, &iv);
				memory_handler(CLIENT, socket_d, TAG_LEN, &tag);
				memory_handler(CLIENT, socket_d, 1, &opcode);
				memory_handler(CLIENT, socket_d, 1, &ciphertext);

				rc = RAND_bytes(iv, IV_LEN);
				if(rc != 1){
				    error_handler("iv generation failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				opcode[0] = '7';
				plaintext[0] = DUMMY_BYTE;

				//	AAD SERIALIZATION
				aad_len = 1 + sizeof(unsigned int);	
				memory_handler(CLIENT, socket_d, aad_len, &aad);
				memory_handler(CLIENT, socket_d, sizeof(int), &aad_len_byte);

				serialize_int(aad_len, aad_len_byte);
				memcpy(aad, opcode, sizeof(unsigned char));
				memcpy(&aad[1], nonce, NONCE_LEN);

				//	CIPHERTEXT LEN SERIALIZATION
				ct_len = gcm_encrypt(plaintext, 1, aad, aad_len, this_user->session_key, iv, IV_LEN, ciphertext, tag);
				if(ct_len <= 0){
				    error_handler("encrypt() failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				memory_handler(CLIENT, socket_d, sizeof(int), &ct_len_byte);
				serialize_int(ct_len, ct_len_byte);

				//	PAYLOAD LEN SERIALIZATION
				payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(CLIENT, socket_d, sizeof(int), &payload_len_byte);
				serialize_int(payload_len, payload_len_byte);

				//	BUILD MESSAGE
				msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(CLIENT, socket_d, msg_len, &resp_msg);

				memcpy(resp_msg, payload_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int)], aad_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int)], aad, aad_len);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int)], ciphertext, ct_len);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len], tag, TAG_LEN);
				memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], iv, IV_LEN);

				//	SEND PACKET
				if((ret = send(socket_d, (void*)resp_msg, msg_len, 0)) < 0){
				    error_handler("send() failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				// RECEIVE SERVER REPLAY

				// READ PAYLOAD_LEN
				memory_handler(CLIENT, socket_d, sizeof(int), &rcv_msg);
				if((ret = read_byte(socket_d, (void*)rcv_msg, sizeof(int))) < 0){
				    error_handler("recv() [rcv_msg] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 1");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				memcpy(&msg_len, rcv_msg, sizeof(int));

				// READ AAD_LEN & AAD
				if((ret = read_byte(socket_d, (void*)aad_len_byte, sizeof(int))) < 0){
				    error_handler("recv() [aad_len_byte] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 2");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				memcpy(&aad_len, aad_len_byte, sizeof(int));
				if((ret = read_byte(socket_d, (void*)aad, aad_len)) < 0){
				    error_handler("recv() [aad] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 3");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				cmd = int(aad[0]) - OFFSET;
				memcpy(&sv_counter, &aad[1], sizeof(unsigned int));
				if(this_user->s_counter != sv_counter || sv_counter == UINT_MAX){
					error_handler("Session exiperd");
					free_var(CLIENT);
					close(socket_d);
					exit(0);
				}	
				this_user->s_counter++;

				// READ CT_LEN & CIPHERTEXT
				if((ret = read_byte(socket_d, (void*)ct_len_byte, sizeof(int))) < 0){
				    error_handler("recv() [ct_len_byte] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 4");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				memcpy(&ct_len, ct_len_byte, sizeof(int));

				if((ret = read_byte(socket_d, (void*)ciphertext, ct_len)) < 0){
				    error_handler("recv() [ciphertext] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 5");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				// READ TAG
				if((ret = read_byte(socket_d, (void*)tag, TAG_LEN)) < 0){
				    error_handler("recv() [tag] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 6");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				// READ IV
				if((ret = read_byte(socket_d, (void*)iv, IV_LEN)) < 0){
				    error_handler("recv() [iv] failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}
				if(ret == 0){
				    error_handler("nothing to read! 7");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				// DECRYPT CT
				ret = gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, this_user->session_key, iv, IV_LEN, plaintext);
				if(ret < 0){
				    error_handler("decrypt failed");
				    free_var(CLIENT);
				    close(socket_d);
				    exit(0);
				}

				memset(this_user->session_key, '\0', 32);
				free(this_user->session_key);
				free_var(CLIENT);
				this_user = NULL;
				close(socket_d);
				cout << "Exit program..." << endl;
				exit(0);
				break;
			}
		    default:	// technically not possible
		        	break;
		}
		cout << endl << endl;
    }
    return 0; //Unreachable code
}
