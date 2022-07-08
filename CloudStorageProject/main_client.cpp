/*		CLIENT -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

#include "data_struct.h"

using namespace std;

/* TEST ONLY */
unsigned char key[] = "password12345678password12345678";
//unsigned char iv[] = "123456789012";
/*	END*/


int main(){

	int socket_d, ret, cmd;
	unsigned char *command = NULL, *command_copy = NULL, *path1 = NULL, *path2 = NULL;
	struct sockaddr_in sv_addr;
    
	//	Cleanup and initialization	 
	memset(&sv_addr, 0, sizeof(sv_addr));
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_port = htons(4242); //RANDOM port number
	if((ret = inet_pton(AF_INET, "127.0.0.1", &(sv_addr.sin_addr))) == 0)
	    error_handler("address format not valid");

	if((socket_d = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	    error_handler("socket creation failed");

	cout << "> Socket created successfully!" << endl;

	if((ret = connect(socket_d, (struct sockaddr*)&sv_addr, sizeof(sv_addr))) < 0)
		error_handler("connect() failed");

	for(int i = 0; i < 1024; i++)
		cl_free_buf[i] = 0;

	print_man();

    // Endless loop - Managing entire session 

	while(1) {
		memory_handler(1, socket_d, 128, &command);
		memory_handler(1, socket_d, 128, &command_copy);
       
		cout << "Enter a message.." << endl;
		cin.getline((char*)command, 128);
		if((char)command[0] == '\0')
			continue;

		strncpy((char*)command_copy, (char*)command, strlen((char*)command));

		if((cmd = get_cmd((char*)command)) < 0)
			error_handler("Command not found. Type 'man' for the Manual");

		if(cmd == 5){
			memory_handler(1, socket_d, 64, &path1);
			memory_handler(1, socket_d, 64, &path2);
		}
		else if(cmd == 3 || cmd == 4 || cmd == 6)
			memory_handler(1, socket_d, 64, &path1);

		split_path(command_copy, &path1, &path2);
		if(path1)
			cout << "path1: " << path1 << endl;
		if(path2)
			cout << "path2: " << path2 << endl;

	        switch(cmd){
	        	case MAN:{	// man command
                		print_man();
				break;
			}
	        	case LIST:{	// ls command		[payload_len][aad_len]{[opcode][nonce]}[cyph_len][dummy_byte][tag][iv]
				int payload_len, ct_len, aad_len, rc, msg_len;
    				unsigned char *rcv_msg, *resp_msg, *tag, *iv, *plaintext, *ciphertext, *opcode, *nonce, *aad, *aad_len_byte, *payload_len_byte, *ct_len_byte;			
		
				//	MALLOC & RAND VARIABLES
				memory_handler(1, socket_d, NONCE_LEN, &nonce);
				memory_handler(1, socket_d, TAG_LEN, &tag);
				memory_handler(1, socket_d, 1, &opcode);
				memory_handler(1, socket_d, 512, &ciphertext);
				memory_handler(1, socket_d, IV_LEN, &iv);

				rc = RAND_bytes(nonce, NONCE_LEN);
				if(rc != 1){
					error_handler("nonce generation failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				rc = RAND_bytes(iv, IV_LEN);
				if(rc != 1){
					error_handler("iv generation failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				opcode[0] = '2';
				memset(ciphertext, 0, 512);

				//	SERIALIZATION

				//	AAD SERIALIZATION
				aad_len = 1 + NONCE_LEN;	//opcode + lunghezza nonce -- opcode = unsigned char
				memory_handler(1, socket_d, aad_len, &aad);			
				memory_handler(1, socket_d, aad_len, &aad_len_byte);
				serialize_int(aad_len, aad_len_byte);
				memcpy(aad, opcode, sizeof(unsigned char));
				memcpy(&aad[1], nonce, NONCE_LEN);

				//	CIPHERTEXT LEN SERIALIZATION
				memory_handler(1, socket_d, 512, &plaintext);
				plaintext[0] = DUMMY_BYTE;
				ct_len = gcm_encrypt(plaintext, sizeof(char), aad, aad_len, key, iv, IV_LEN, ciphertext, tag);
				if(ct_len <= 0){ 
					error_handler("encrypt() failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}

				memory_handler(1, socket_d, ct_len, &ct_len_byte);
				serialize_int(ct_len, ct_len_byte);

				//	PAYLOAD LEN SERIALIZATION
				payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(1, socket_d, sizeof(int), &payload_len_byte);
				serialize_int(payload_len, payload_len_byte);

				//	BUILD MESSAGE (resp_msg)
				msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(1, socket_d, msg_len, &resp_msg);

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
					free_var(1);
					close(socket_d);
					exit(0);
				}

				cout << endl << endl;

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

				//	RECEIVE SERVER REPLAY

				//	READ PAYLOAD_LEN
				memory_handler(1, socket_d, sizeof(int), &rcv_msg);
				if((ret = read_byte(socket_d, (void*)rcv_msg, sizeof(int))) < 0){
					error_handler("recv() [rcv_msg] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 1");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				memcpy(&msg_len, rcv_msg, sizeof(int));

				//	READ AAD_LEN & AAD
				if((ret = read_byte(socket_d, (void*)aad_len_byte, sizeof(int))) < 0){
					error_handler("recv() [aad_len_byte] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 2");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				memcpy(&aad_len, aad_len_byte, sizeof(int));
				if((ret = read_byte(socket_d, (void*)aad, aad_len)) < 0){
					error_handler("recv() [aad] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 3");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				cmd = int(aad[0]) - OFFSET;			
				
				//	READ CT_LEN & CIPHERTEXT
				if((ret = read_byte(socket_d, (void*)ct_len_byte, sizeof(int))) < 0){
					error_handler("recv() [ct_len_byte] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 4");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				memcpy(&ct_len, ct_len_byte, sizeof(int));

				if((ret = read_byte(socket_d, (void*)ciphertext, ct_len)) < 0){
					error_handler("recv() [ciphertext] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 5");
					free_var(1);
					close(socket_d);
					exit(0);
				}

				//	READ TAG
				if((ret = read_byte(socket_d, (void*)tag, TAG_LEN)) < 0){
					error_handler("recv() [tag] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 6");
					free_var(1);
					close(socket_d);
					exit(0);
				}

				//	READ IV
				if((ret = read_byte(socket_d, (void*)iv, IV_LEN)) < 0){
					error_handler("recv() [iv] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 7");
					free_var(1);
					close(socket_d);
					exit(0);
				}

				//	DECRYPT CT
				ret = gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, key, iv, IV_LEN, plaintext);
				if(ret < 0){
					error_handler("decrypt failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				cout << "These are the files in your cloud folder: " << endl;
				char *token = strtok((char*)plaintext, "|");
				while(token != NULL){
					cout << token << endl;
					token = strtok(NULL, "|");
				}
				free_var(1);
				break;
			}
			case UPLOAD:{	// up command 1 - request - [pay_len][aad_len]{[nonce][opcode][file_size_req]}[ciph_len]([ciphertext - file_name])[TAG][IV]
				int payload_len, ct_len, aad_len, rc, msg_len, file_size;
                unsigned char *rcv_msg, *resp_msg, *tag, *iv, *plaintext, *ciphertext, *opcode, *nonce, *aad, *aad_len_byte, *payload_len_byte, *ct_len_byte, *file_size_byte;
				unsigned char flag;
				struct stat *s_buf;	

				//	MALLOC & RAND VARIABLES
				memory_handler(1, socket_d, 64, &plaintext);
				memory_handler(1, socket_d, NONCE_LEN, &nonce);
				memory_handler(1, socket_d, IV_LEN, &iv);
				memory_handler(1, socket_d, TAG_LEN, &tag);
				memory_handler(1, socket_d, 1, &opcode);
				memory_handler(1, socket_d, 512, &ciphertext);

				rc = RAND_bytes(nonce, NONCE_LEN);
				if(rc != 1){
					error_handler("nonce generation failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				rc = RAND_bytes(iv, IV_LEN);
				if(rc != 1){
					error_handler("iv generation failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}

				opcode[0] = '3';
				memset(ciphertext, 0, 512);
				
				//	FILE STAT
				s_buf = (struct stat*)malloc(sizeof(struct stat));
				if(!s_buf){
					error_handler("malloc() [buffer stat] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				cl_free_buf[cl_index_free_buf] = (unsigned char*)s_buf;
				cl_index_free_buf++;

				if((stat((char*)path1, s_buf)) < 0){
					error_handler("stat failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				file_size = s_buf->st_size;

				memory_handler(1, socket_d, file_size, &file_size_byte);
				serialize_int(file_size, file_size_byte);
				strncpy((char*)plaintext, (char*)path1, strlen((char*)path1));

				//	SERIALIZATION UP-1
		
				//	AAD SERIALIZATION
				aad_len = 1 + NONCE_LEN + sizeof(int);	//opcode + lunghezza nonce + int(file size) -- opcode = unsigned char
				memory_handler(1, socket_d, aad_len, &aad);
				memory_handler(1, socket_d, aad_len, &aad_len_byte);

				serialize_int(aad_len, aad_len_byte);
				memcpy(aad, opcode, sizeof(unsigned char));
				memcpy(&aad[1], nonce, NONCE_LEN);
				memcpy(&aad[17], &file_size, sizeof(int));	// no compilation/execution errors, check functionality when implemented server side

				//	CIPHERTEXT LEN SERIALIZATION
				ct_len = gcm_encrypt(plaintext, strlen((char*)plaintext), aad, aad_len, key, iv, IV_LEN, ciphertext, tag);
				if(ct_len <= 0){ 
					error_handler("encrypt() failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				memory_handler(1, socket_d, ct_len, &ct_len_byte);
				serialize_int(ct_len, ct_len_byte);

				//	PAYLOAD LEN SERIALIZATION
				payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;	// ricalcolo per upload
				memory_handler(1, socket_d, sizeof(int), &payload_len_byte);
				serialize_int(payload_len, payload_len_byte);

				//	BUILD MESSAGE (resp_msg)
				msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
				memory_handler(1, socket_d, msg_len, &resp_msg);

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
					free_var(1);
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

				//	RECEIVE SERVER REPLAY

				//	READ PAYLOAD_LEN
				memory_handler(1, socket_d, sizeof(int), &rcv_msg);
				if((ret = read_byte(socket_d, (void*)rcv_msg, sizeof(int))) < 0){
					error_handler("recv() [rcv_msg] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 1");	// double free if server down -- #malloc = 12, index = 12
					free_var(1);
					close(socket_d);
					exit(0);
				}
				memcpy(&msg_len, rcv_msg, sizeof(int));

				//	READ AAD_LEN & AAD
				if((ret = read_byte(socket_d, (void*)aad_len_byte, sizeof(int))) < 0){
					error_handler("recv() [aad_len_byte] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 2");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				memcpy(&aad_len, aad_len_byte, sizeof(int));
				if((ret = read_byte(socket_d, (void*)aad, aad_len)) < 0){
					error_handler("recv() [aad] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 3");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				cmd = int(aad[0]) - OFFSET;			
				flag = aad[17];
				if((int(flag) - OFFSET) == 0){
					// interrompi tutto
					error_handler("Upload error");
					free_var(1);
					break;
				}

				//	READ CT_LEN & CIPHERTEXT
				if((ret = read_byte(socket_d, (void*)ct_len_byte, sizeof(int))) < 0){
					error_handler("recv() [ct_len_byte] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 4");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				memcpy(&ct_len, ct_len_byte, sizeof(int));

				if((ret = read_byte(socket_d, (void*)ciphertext, ct_len)) < 0){
					error_handler("recv() [ciphertext] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 5");
					free_var(1);
					close(socket_d);
					exit(0);
				}

				//	READ TAG
				if((ret = read_byte(socket_d, (void*)tag, TAG_LEN)) < 0){
					error_handler("recv() [tag] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 6");
					free_var(1);
					close(socket_d);
					exit(0);
				}

				//	READ IV
				if((ret = read_byte(socket_d, (void*)iv, IV_LEN)) < 0){
					error_handler("recv() [iv] failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				if(ret == 0){
					error_handler("nothing to read! 7");
					free_var(1);
					close(socket_d);
					exit(0);
				}

				//	DECRYPT CT
				ret = gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, key, iv, IV_LEN, plaintext);
				if(ret < 0){
					error_handler("decrypt failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				cout << "Ricevuta conferma per upload" << endl;

				//	SENDING CHUNK

				// clean up variables
				memset(iv, 0, IV_LEN);
				memset(tag, 0, TAG_LEN);
				memset(nonce, 0, NONCE_LEN);
				ct_len = 0;
				aad_len = 2 + NONCE_LEN;
				payload_len = 0;
				msg_len = 0;
				rc = 0;

				//	FILE OPENING
				FILE *fd;
				unsigned char *data_pt, *data_ct, *data_aad, *data_aad_len_byte, *data_ct_len_byte, *data_payload_len_byte, *data_resp_msg, *file_buffer;

				memory_handler(1, socket_d, CHUNK, &data_pt);
				memory_handler(1, socket_d, CHUNK, &data_ct);
				memory_handler(1, socket_d, aad_len, &data_aad);
				memory_handler(1, socket_d, file_size, &file_buffer);

				fd = fopen((char*)path1, "rb");
				if(!fd){
					error_handler("file opening failed");
					free_var(1);
					close(socket_d);
					exit(0);
				}
				fread(file_buffer, file_size, 1, fd);
				
				if(file_size > CHUNK){
					cout << "File greater than 1Mb - Proceding to send chunks" << endl;
					for(int i = 0; i < file_size - CHUNK && file_size > CHUNK; i += CHUNK){	// If file_size is greater than 1 chunk (1mb) then send the file divided in chunk but not the last
						memcpy(data_pt, &file_buffer[i], CHUNK);
						// RANDOM VALUES
						rc = RAND_bytes(nonce, NONCE_LEN);
						if(rc != 1){
							error_handler("nonce generation failed");
							free_var(1);
							close(socket_d);
							exit(0);
						}
						rc = RAND_bytes(tag, TAG_LEN);
						if(rc != 1){
							error_handler("nonce generation failed");
							free_var(1);
							close(socket_d);
							exit(0);
						}
						rc = RAND_bytes(iv, IV_LEN);
						if(rc != 1){
							error_handler("nonce generation failed");
							free_var(1);
							close(socket_d);
							exit(0);
						}

						// AAD INITIALIZATION
						flag = '0';
						opcode[0] = '3';

						memory_handler(1, socket_d, aad_len, &data_aad_len_byte);

						serialize_int(aad_len, data_aad_len_byte);
						memcpy(aad, opcode, sizeof(unsigned char));
						memcpy(&aad[1], nonce, NONCE_LEN);
						memcpy(&aad[17], &flag, sizeof(unsigned char));
						
						// CT SERIALIZATION
						ct_len = gcm_encrypt(data_pt, strlen((char*)data_pt), data_aad, aad_len, key, iv, IV_LEN, data_ct, tag);
						if(ct_len <= 0){ 
							error_handler("encrypt() failed");
							free_var(1);
							close(socket_d);
							exit(0);
						}
						memory_handler(1, socket_d, ct_len, &data_ct_len_byte);
						serialize_int(ct_len, data_ct_len_byte);

						// PAYLOAD SERIALIZATION
						payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;	
						memory_handler(1, socket_d, sizeof(int), &data_payload_len_byte);
						serialize_int(payload_len, data_payload_len_byte);

						//	BUILD MESSAGE (resp_msg)
						msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
						memory_handler(1, socket_d, msg_len, &data_resp_msg);

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
							free_var(1);
							close(socket_d);
							exit(0);
						}
						// end send
						cout << "Sent chunk #" << i << endl;
						memset(data_pt, 0, CHUNK); 
					}
				}
				//else{		// send last chunk or the single chunk composing the file
					cout << "Proceding to send the last chunk" << endl;
					memcpy(data_pt, file_buffer, file_size);

					// RANDOM VALUES
					rc = RAND_bytes(nonce, NONCE_LEN);
					if(rc != 1){
						ERR_print_errors_fp(stdout);
						error_handler("nonce generation failed");
						free_var(1);
						close(socket_d);
						exit(0);
					}
					rc = RAND_bytes(tag, TAG_LEN);
					if(rc != 1){
						error_handler("tag generation failed");
						free_var(1);
						close(socket_d);
						exit(0);
					}
					rc = RAND_bytes(iv, IV_LEN);
					if(rc != 1){
						error_handler("iv generation failed");
						free_var(1);
						close(socket_d);
						exit(0);
					}

					// AAD INITIALIZATION
					flag = '0';
					opcode[0] = '3';

					memory_handler(1, socket_d, aad_len, &data_aad_len_byte);
					serialize_int(aad_len, data_aad_len_byte);
					memcpy(aad, opcode, sizeof(unsigned char));
					memcpy(&aad[1], nonce, NONCE_LEN);
					memcpy(&aad[17], &flag, sizeof(unsigned char));
						
					// CT SERIALIZATION
					ct_len = gcm_encrypt(data_pt, strlen((char*)data_pt), data_aad, aad_len, key, iv, IV_LEN, data_ct, tag);
					if(ct_len <= 0){ 
						error_handler("encrypt() failed");
						free_var(1);
						close(socket_d);
						exit(0);
					}
					memory_handler(1, socket_d, ct_len, &data_ct_len_byte);
					serialize_int(ct_len, data_ct_len_byte);

					// PAYLOAD SERIALIZATION
					payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;	
					memory_handler(1, socket_d, sizeof(int), &data_payload_len_byte);
					serialize_int(payload_len, data_payload_len_byte);

					//	BUILD MESSAGE (resp_msg)
					msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
					memory_handler(1, socket_d, msg_len, &data_resp_msg);

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
						free_var(1);
						close(socket_d);
						exit(0);
					}
					memset(data_pt, 0, CHUNK);
				//}
				
				//	RECEIVING OK
				free_var(1);
				break;
			}
		    case DOWNLOAD:{	// dl command

				free_var(1);
				break;
			}
		    case RENAME:{	// mv command

				free_var(1);
				break;
			}
		    case DELETE:{	// rm command request:  [pay_len][aad_len]{[nonce][opcode]}[ciph_len]([ciphertext - file_name])[TAG][IV]
                int payload_len, ct_len, aad_len, rc, msg_len;
                unsigned char *rcv_msg, *resp_msg, *tag, *iv, *plaintext, *ciphertext, *opcode, *nonce, *aad, *aad_len_byte, *payload_len_byte, *ct_len_byte;
                //unsigned char flag;
                struct stat *s_buf;

                //	MALLOC & RAND VARIABLES
                memory_handler(1, socket_d, 64, &plaintext);
                memory_handler(1, socket_d, NONCE_LEN, &nonce);
                memory_handler(1, socket_d, IV_LEN, &iv);
                memory_handler(1, socket_d, TAG_LEN, &tag);
                memory_handler(1, socket_d, 1, &opcode);
                memory_handler(1, socket_d, 512, &ciphertext);

                rc = RAND_bytes(nonce, NONCE_LEN);
                if(rc != 1){
                    error_handler("nonce generation failed");
                    free_var(1);
                    close(socket_d);
                    exit(0);
                }
                rc = RAND_bytes(iv, IV_LEN);
                if(rc != 1){
                    error_handler("iv generation failed");
                    free_var(1);
                    close(socket_d);
                    exit(0);
                }

                opcode[0] = '6';
                memset(ciphertext, 0, 512);

                /*
                //	FILE STAT
                s_buf = (struct stat*)malloc(sizeof(struct stat));
                if(!s_buf){
                    error_handler("malloc() [buffer stat] failed");
                    free_var(1);
                    close(socket_d);
                    exit(0);
                }
                cl_free_buf[cl_index_free_buf] = (unsigned char*)s_buf;
                cl_index_free_buf++;

                if((stat((char*)path1, s_buf)) < 0){
                    error_handler("stat failed");
                    free_var(1);
                    close(socket_d);
                    exit(0);
                }*/


                //	DELETE RM-1

                //	AAD SERIALIZATION
                aad_len = 1 + NONCE_LEN;	//opcode + lunghezza nonce -- opcode = unsigned char
                memory_handler(1, socket_d, aad_len, &aad);
                memory_handler(1, socket_d, aad_len, &aad_len_byte);

                serialize_int(aad_len, aad_len_byte);
                memcpy(aad, opcode, sizeof(unsigned char));
                memcpy(&aad[1], nonce, NONCE_LEN);

                //	CIPHERTEXT LEN SERIALIZATION
                ct_len = gcm_encrypt(plaintext, strlen((char*)plaintext), aad, aad_len, key, iv, IV_LEN, ciphertext, tag);
                if(ct_len <= 0){
                    error_handler("encrypt() failed");
                    free_var(1);
                    close(socket_d);
                    exit(0);
                }
                memory_handler(1, socket_d, ct_len, &ct_len_byte);
                serialize_int(ct_len, ct_len_byte);

                //	PAYLOAD LEN SERIALIZATION
                payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
                memory_handler(1, socket_d, sizeof(int), &payload_len_byte);
                serialize_int(payload_len, payload_len_byte);

                //	BUILD MESSAGE (resp_msg)
                msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
                memory_handler(1, socket_d, msg_len, &resp_msg);

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
                    free_var(1);
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

                //	TODO RECEIVE SERVER REPLAY to confirm the file deleted


                free_var(1);
				break;
			}
		    default:	// technically not possible
		        	break;
		}
		
    }
    return 0; //Unreachable code
}