/*		SERVER -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

#include "./../util/data_struct.h"

using namespace std;

int main(){

	int listner_socket, new_socket, ret, option = 1, k, fdmax;
	unsigned int sv_counter = 0;
	struct sockaddr_in my_addr, client_addr;
	user *list = NULL;

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

	for(int i = 0; i < 1024; i++)
		sv_free_buf[i] = 0;

	//	Endless loop - Managing client(s) request(s) - Single process with multiple descriptors 
	unsigned char *session_key = NULL;
	while(1){
		read_set = master;
		select(fdmax + 1, &read_set, NULL, NULL, NULL);
		for(k = 0; k <= fdmax; k++){ // Scan for ready socket
			if(FD_ISSET(k, &read_set)){
				if(k == listner_socket){ // Listner Socket - New connection request
					if((new_socket = accept(listner_socket, (struct sockaddr*)&client_addr, &len)) < 0){
						error_handler("accept() failed");
						exit(0);
					}
					
					FD_SET(new_socket, &master);
					if(new_socket > fdmax)
						fdmax = new_socket;
				}
				else{ // Serving client request
					int ct_len, aad_len, msg_len, cmd;
					unsigned int c_counter;
					unsigned char *rcv_msg, *plaintext, *ciphertext, *ct_len_byte, *aad_len_byte, *aad, *tag, *iv;	
					unsigned char flag_check = '1';		
					char *dirname, *username;
					
					if(!session_key){
						session_key = (unsigned char*)malloc(EVP_CIPHER_key_length(EVP_aes_256_gcm()));
						if(!session_key){
							error_handler("Malloc failed");
							close(k);
							free_var(SERVER);
							exit(0);
						}
					}
					if((ret = is_auth(k, list)) != 1)
						s_authenticate(k, &list, session_key); 
					
					dirname = (char*)malloc(MAX_PATH);
					if(!dirname){
						error_handler("Malloc failed");
						close(k);
						free_var(SERVER);
						exit(0);
					}
					username = (char*)malloc(11);
					if(!username){
						error_handler("Malloc failed");
							close(k);
							free_var(SERVER);
							exit(0);
					}
					user *client = get_user(k, list);
					username = client->username;
					if(!username){
						error_handler("username not found");
						close(k);
						free_var(SERVER);
						exit(0);
					}

					getcwd(dirname, MAX_PATH);
					strncat(dirname, "/server_src/", strlen("/server_src/"));
					strncat(dirname, username, 10);
					strncat(dirname, "/", strlen("/"));

					cout << "Perforing operation..." << endl;
					//	READ PAYLOAD_LEN
					memory_handler(SERVER, k, sizeof(int), &rcv_msg);
					if((ret = read_byte(k, (void*)rcv_msg, sizeof(int))) < 0){
						error_handler("recv() [rcv_msg] failed, closing socket");
						close(k);
						free_var(SERVER);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! Client disconnected...");
						close(k);
						free_var(SERVER);
						//exit(0);
						break;
					}
					memcpy(&msg_len, rcv_msg, sizeof(int));

					//	READ AAD_LEN & AAD
					memory_handler(SERVER, k, sizeof(int), &aad_len_byte);
					if((ret = read_byte(k, (void*)aad_len_byte, sizeof(int))) < 0){
						error_handler("recv() [aad_len_byte] failed, closing socket");
						close(k);
						free_var(SERVER);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! Client disconnected...");
						close(k);
						free_var(SERVER);
						exit(0);
					}
					memcpy(&aad_len, aad_len_byte, sizeof(int));
					memory_handler(SERVER, k, aad_len, &aad);
					if((ret = read_byte(k, (void*)aad, aad_len)) < 0){
						error_handler("recv() [aad] failed");
						close(k);
						free_var(SERVER);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! Client disconnected...");
						close(k);
						free_var(SERVER);
						exit(0);
					}
					cmd = int(aad[0]) - OFFSET;			
					memcpy(&c_counter, &aad[1], sizeof(unsigned int));
					if(sv_counter != c_counter || c_counter == UINT_MAX){
						error_handler("Session exiperd");
						free_var(SERVER);
						close(k);
						exit(0);
					}

					//	READ CT_LEN & CIPHERTEXT
					memory_handler(SERVER, k, sizeof(int), &ct_len_byte);
					if((ret = read_byte(k, (void*)ct_len_byte, sizeof(int))) < 0){
						error_handler("recv() [ct_len_byte] failed");
						close(k);
						free_var(SERVER);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! 4");
						close(k);
						free_var(SERVER);
						exit(0);
					}
					memcpy(&ct_len, ct_len_byte, sizeof(int));

					memory_handler(SERVER, k, ct_len, &ciphertext);
					if((ret = read_byte(k, (void*)ciphertext, ct_len)) < 0){
						error_handler("recv() [ciphertext] failed");
						close(k);
						free_var(SERVER);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! 5");
						close(k);
						free_var(SERVER);
						exit(0);
					}

					//	READ TAG
					memory_handler(SERVER, k, TAG_LEN, &tag);
					if((ret = read_byte(k, (void*)tag, TAG_LEN)) < 0){
						error_handler("recv() [tag] failed");
						close(k);
						free_var(SERVER);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! 6");
						close(k);
						free_var(SERVER);
						exit(0);
					}

					//	READ IV
					memory_handler(SERVER, k, IV_LEN, &iv);
					if((ret = read_byte(k, (void*)iv, IV_LEN)) < 0){
						error_handler("recv() [iv] failed");
						close(k);
						free_var(SERVER);
						exit(0);
					}
					if(ret == 0){
						error_handler("nothing to read! 7");
						close(k);
						free_var(SERVER);
						exit(0);
					}

					//	DECRYPT CT
					memory_handler(SERVER, k, ct_len, &plaintext);
					ret = gcm_decrypt(ciphertext, ct_len, aad, aad_len, tag, session_key, iv, IV_LEN, plaintext);
					if(ret < 0){
						close(k);
						free_var(SERVER);
						exit(0);
					}

					int res_check_command = check_cmd(plaintext, cmd);

					if(res_check_command == -1)
						flag_check = '0';
					else
						flag_check = '1';


					switch(cmd){
						case 2:{	// ls 	[payload_len][aad_len]{[opcode][nonce]}[cyph_len][file_name][tag][iv]
							unsigned char *resp_msg_ls = NULL, *opcode_ls = NULL, *nonce_ls = NULL, *ciphertext_ls = NULL, *plaintext_ls = NULL, *ct_len_byte_ls = NULL;
							unsigned char *aad_len_byte_ls = NULL, *aad_ls = NULL, *tag_ls = NULL, *iv_ls = NULL, *payload_len_byte_ls = NULL;
							int ct_len_ls, aad_len_ls, msg_len_ls, rc_ls, payload_len_ls;

							DIR *dir;
							struct dirent *en;
							unsigned char *buf, *name_tmp;
							unsigned char flag = '1';
							int dim = 0, count = 0, num_file = 0;

							num_file = get_num_file(dirname);
							dir = opendir(dirname);
							if(dir){
								while((en = readdir(dir)) != NULL){
									if(!strncmp(en->d_name, ".", strlen(".")) || !strncmp(en->d_name, "..", strlen("..")))
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
								free_var(SERVER);
								exit(0);
							}
							if(dim == 0){
								memory_handler(SERVER, k, 22, &plaintext_ls);
								memory_handler(SERVER, k, 22, &ciphertext_ls);
								strncpy((char*)plaintext_ls, "Your folder is empty!", 22);
								flag = '0';
								goto replay_ls;
							}
							dir = opendir(dirname);
							if(dir){
								buf = (unsigned char*)malloc(dim+1);
								while((en = readdir(dir)) != NULL){
									if(!strncmp(en->d_name, ".", strlen(".")) || !strncmp(en->d_name, "..", strlen("..")))
										continue;
									
									//	copy file names into buf
									name_tmp = (unsigned char*)calloc((strlen(en->d_name) + 2), sizeof(unsigned char));
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
								free_var(SERVER);

								free(name_tmp);
								free(buf);
								exit(0);
							}
							
							//	MALLOC & RAND VARIABLES
							memory_handler(SERVER, k, strlen((char*)buf), &plaintext_ls);
							memory_handler(SERVER, k, strlen((char*)buf), &ciphertext_ls);
							strncpy((char*)plaintext_ls, (char*)buf, strlen((char*)buf));
replay_ls:
							memory_handler(SERVER, k, NONCE_LEN, &nonce_ls);
							memory_handler(SERVER, k, TAG_LEN, &tag_ls);
							memory_handler(SERVER, k, 1, &opcode_ls);
							memory_handler(SERVER, k, IV_LEN, &iv_ls);

							/*rc_ls = RAND_bytes(nonce_ls, NONCE_LEN);
							if(rc_ls != 1){
								error_handler("nonce generation failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}*/

							rc_ls = RAND_bytes(iv, IV_LEN);
							if(rc_ls != 1){
								error_handler("iv generation failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}

							opcode_ls[0] = '2';

							//	SERIALIZATION

							//	AAD SERIALIZATION
							aad_len_ls = 2 + sizeof(unsigned int);
							memory_handler(SERVER, k, aad_len_ls, &aad_ls);
							memory_handler(SERVER, k, sizeof(int), &aad_len_byte_ls);
							
							serialize_int(aad_len_ls, aad_len_byte_ls);
							memcpy(aad_ls, opcode_ls, sizeof(unsigned char));
							sv_counter++;
							memcpy(&aad_ls[1], &sv_counter, sizeof(unsigned int));
							memcpy(&aad_ls[5], &flag, sizeof(unsigned char));

							//	CIPHERTEXT LEN SERIALIZATION
							ct_len_ls = gcm_encrypt(plaintext_ls, strlen((char*)plaintext_ls), aad_ls, aad_len_ls, session_key, iv_ls, IV_LEN, ciphertext_ls, tag_ls);
							if(ct_len_ls <= 0){ 
								error_handler("encrypt() failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							memory_handler(SERVER, k, sizeof(int), &ct_len_byte_ls);
							serialize_int(ct_len_ls, ct_len_byte_ls);

							//	PAYLOAD LEN SERIALIZATION
							payload_len_ls = sizeof(int) + aad_len_ls + sizeof(int) + ct_len_ls + TAG_LEN + IV_LEN;
							memory_handler(SERVER, k, sizeof(int), &payload_len_byte_ls);
							
							serialize_int(payload_len_ls, payload_len_byte_ls);

							//	BUILD MESSAGE (resp_msg)
							msg_len_ls = sizeof(int) + sizeof(int) + aad_len_ls + sizeof(int) + ct_len_ls + TAG_LEN + IV_LEN;
							memory_handler(SERVER, k, msg_len_ls, &resp_msg_ls);

							memcpy(resp_msg_ls, payload_len_byte_ls, sizeof(int));
							memcpy((unsigned char*)&resp_msg_ls[sizeof(int)], aad_len_byte_ls, sizeof(int));
							memcpy((unsigned char*)&resp_msg_ls[sizeof(int) + sizeof(int)], aad_ls, aad_len_ls);
							memcpy((unsigned char*)&resp_msg_ls[sizeof(int) + sizeof(int) + aad_len_ls], ct_len_byte_ls, sizeof(int));
							memcpy((unsigned char*)&resp_msg_ls[sizeof(int) + sizeof(int) + aad_len_ls + sizeof(int)], ciphertext_ls, ct_len_ls);
							memcpy((unsigned char*)&resp_msg_ls[sizeof(int) + sizeof(int) + aad_len_ls + sizeof(int) + ct_len_ls], tag_ls, TAG_LEN);
							memcpy((unsigned char*)&resp_msg_ls[sizeof(int) + sizeof(int) + aad_len_ls + sizeof(int) + ct_len_ls + TAG_LEN], iv_ls, IV_LEN);

							//	SEND PACKET
							if((ret = send(k, (void*)resp_msg_ls, msg_len_ls, 0)) < 0){
					    			error_handler("send() failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}

							free_var(SERVER);
							break;
						}
						case 3:{	// up 2:	[payload_len][aad_len]{[opcode][nonce][flag]}[cyph_len][file_name][tag][iv]
							unsigned char *resp_msg_up = NULL, *rcv_msg_up = NULL, *opcode_up = NULL, *nonce_up = NULL, *ciphertext_up = NULL, *plaintext_up = NULL, *ct_len_byte_up = NULL;
							unsigned char *aad_len_byte_up = NULL, *aad_up = NULL, *tag_up = NULL, *iv_up = NULL, *payload_len_byte_up = NULL;
							int ct_len_up, aad_len_up, msg_len_up, rc_up, payload_len_up;
							unsigned int c_counter;

							long int file_size;					
							unsigned char flag = flag_check;
							char *fullpath;

							fullpath = (char*)calloc(MAX_PATH, sizeof(char));
							if(!fullpath){
								error_handler("malloc() [fullpath] failed, aborting");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							strncpy(fullpath, dirname, strlen(dirname));
							strncat(fullpath, (char*)plaintext, strlen((char*)plaintext));

							if(flag == '0'){	// path traversal
								memory_handler(SERVER, k, 25, &plaintext_up);
								memory_handler(SERVER, k, 25, &ciphertext_up);
								strncpy((char*)plaintext_up, "Warning: path traversing", 25);
							}
							else{	// Check ok, no path traversal
								if(access(fullpath, F_OK) == 0){	// File already exists, upload failed -- vedi commento a lato di plaintext sotto
									memory_handler(SERVER, k, 64, &plaintext_up);
									memory_handler(SERVER, k, 64, &ciphertext_up);
									flag = '0';
									strncpy((char*)plaintext_up, "Upload failed. File already exists on server.", 46);
								}
								else{	// Check ok, file does not exist
									memory_handler(SERVER, k, 1, &plaintext_up);
									memory_handler(SERVER, k, 1, &ciphertext_up);
									plaintext_up[0] = DUMMY_BYTE;
								}
							}
							memcpy(&file_size, &aad[5], sizeof(long int));
							
							if(file_size > 4294967296)
								flag = '0';
				
							//	MALLOC & RAND VARIABLES
							memory_handler(SERVER, k, NONCE_LEN, &nonce_up);
							memory_handler(SERVER, k, TAG_LEN, &tag_up);
							memory_handler(SERVER, k, 1, &opcode_up);
							memory_handler(SERVER, k, IV_LEN, &iv_up);
							

							/*rc_up = RAND_bytes(nonce_up, NONCE_LEN);
							if(rc_up != 1){
								error_handler("nonce generation failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}*/
							rc_up = RAND_bytes(iv, IV_LEN);
							if(rc_up != 1){
								error_handler("iv generation failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							opcode_up[0] = '3';
							

							//	SERIALIZATION

							//	AAD SERIALIZATION
							aad_len_up = 2 + sizeof(unsigned int);
							memory_handler(SERVER, k, aad_len_up, &aad_up);
							memory_handler(SERVER, k, sizeof(int), &aad_len_byte_up);

							serialize_int(aad_len_up, aad_len_byte_up);
							memcpy(aad_up, opcode_up, sizeof(unsigned char));
							sv_counter++;
							memcpy(&aad_up[1], &sv_counter, sizeof(unsigned int));
							memcpy(&aad_up[5], &flag, sizeof(unsigned char));
							//sv_counter++;

							//	CIPHERTEXT LEN SERIALIZATION
							ct_len_up = gcm_encrypt(plaintext_up, strlen((char*)plaintext_up), aad_up, aad_len_up, session_key, iv_up, IV_LEN, ciphertext_up, tag_up);
							if(ct_len_up <= 0){ 
								error_handler("encrypt() failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							memory_handler(SERVER, k, sizeof(int), &ct_len_byte_up);
							serialize_int(ct_len_up, ct_len_byte_up);

							//	PAYLOAD LEN SERIALIZATION
							payload_len_up = sizeof(int) + aad_len_up + sizeof(int) + ct_len_up + TAG_LEN + IV_LEN;
							memory_handler(SERVER, k, sizeof(int), &payload_len_byte_up);
							serialize_int(payload_len_up, payload_len_byte_up);

							//	BUILD MESSAGE (resp_msg)
							msg_len_up = sizeof(int) + sizeof(int) + aad_len_up + sizeof(int) + ct_len_up + TAG_LEN + IV_LEN;
							memory_handler(SERVER, k, msg_len_up, &resp_msg_up);
							
							memcpy(resp_msg_up, payload_len_byte_up, sizeof(int));
							memcpy((unsigned char*)&resp_msg_up[sizeof(int)], aad_len_byte_up, sizeof(int));
							memcpy((unsigned char*)&resp_msg_up[sizeof(int) + sizeof(int)], aad_up, aad_len_up);
							memcpy((unsigned char*)&resp_msg_up[sizeof(int) + sizeof(int) + aad_len_up], ct_len_byte_up, sizeof(int));
							memcpy((unsigned char*)&resp_msg_up[sizeof(int) + sizeof(int) + aad_len_up + sizeof(int)], ciphertext_up, ct_len_up);
							memcpy((unsigned char*)&resp_msg_up[sizeof(int) + sizeof(int) + aad_len_up + sizeof(int) + ct_len_up], tag_up, TAG_LEN);
							memcpy((unsigned char*)&resp_msg_up[sizeof(int) + sizeof(int) + aad_len_up + sizeof(int) + ct_len_up + TAG_LEN], iv_up, IV_LEN);

							//	SEND PACKET
							if((ret = send(k, (void*)resp_msg_up, msg_len_up, 0)) < 0){
					    			error_handler("send() failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							if(flag == '0'){
								error_handler("File already exists or file is too big. Aborting operation...");
								free_var(SERVER);
								break;
							}
							cout << "Upload request accepted, ready to receiving chunk(s)..." << endl;
							
							//	RECEIVING CHUNKS
				
							unsigned char *chunk_buf;
							int chunk_num;
							long int size_res;

							if(file_size % CHUNK != 0)
								chunk_num = (file_size / CHUNK) + 1;
							else
								chunk_num = file_size / CHUNK;

							cout << "Chunk num: " << chunk_num << endl;
							size_res = file_size;
							FILE *new_file;
							new_file = fopen(fullpath, "ab");
							if(!new_file){
								error_handler("file creation failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							//	CLEAN UP VARIABLES
							memset(iv_up, 0, IV_LEN);
							memset(tag_up, 0, TAG_LEN);
							memset(plaintext_up, 0, 1);
							memset(ciphertext_up, 0, 1);
							memset(aad_up, 0, aad_len_up);
							memset(ct_len_byte_up, 0, sizeof(int));
							memset(aad_len_byte_up, 0, sizeof(int));
							memset(payload_len_byte_up, 0, sizeof(int));
							ct_len_up = 0;
							aad_len_up = 0;
							payload_len_up = 0;
							msg_len_up = 0;
							// 	END

							for(int i = 0; i < chunk_num; i++){
								//	READ PAYLOAD_LEN
								memory_handler(SERVER, k, sizeof(int), &rcv_msg_up);
								if((ret = read_byte(k, (void*)rcv_msg_up, sizeof(int))) < 0){
									error_handler("recv() [rcv_msg] failed, closing socket");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}
								if(ret == 0){
									error_handler("nothing to read! Client disconnected...");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free_var(SERVER);
									break;
								}
								memcpy(&msg_len_up, rcv_msg_up, sizeof(int));

								//	READ AAD_LEN & AAD
								memory_handler(SERVER, k, sizeof(int), &aad_len_byte_up);
								if((ret = read_byte(k, (void*)aad_len_byte_up, sizeof(int))) < 0){
									error_handler("recv() [aad_len_byte] failed, closing socket");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}
								if(ret == 0){
									error_handler("nothing to read! Client disconnected...");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}
								memcpy(&aad_len_up, aad_len_byte_up, sizeof(int));
								memory_handler(SERVER, k, aad_len_up, &aad_up);
								if((ret = read_byte(k, (void*)aad_up, aad_len_up)) < 0){
									error_handler("recv() [aad] failed");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}
								if(ret == 0){
									error_handler("nothing to read! Client disconnected...");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}
								memcpy(&c_counter, &aad[1], sizeof(unsigned int));
								sv_counter++;
								if(sv_counter != c_counter || c_counter == UINT_MAX){
									error_handler("Session exiperd");
									free_var(SERVER);
									close(k);
									exit(0);
								}
								flag = aad_up[5];			
								if(flag != '1' && i == chunk_num - 1){
									error_handler("Unexpected error. Waiting last chunk but flag is not '1'. Aborting operation...");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}

								//	READ CT_LEN & CIPHERTEXT
								memory_handler(SERVER, k, sizeof(int), &ct_len_byte_up);
								if((ret = read_byte(k, (void*)ct_len_byte_up, sizeof(int))) < 0){
									error_handler("recv() [ct_len_byte] failed");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}
								if(ret == 0){
									error_handler("nothing to read! 4");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}
								memcpy(&ct_len_up, ct_len_byte_up, sizeof(int));

								memory_handler(SERVER, k, ct_len_up, &ciphertext_up);
								if((ret = read_byte(k, (void*)ciphertext_up, ct_len_up)) < 0){
									error_handler("recv() [ciphertext] failed");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}
								if(ret == 0){
									error_handler("nothing to read! 5");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}

								//	READ TAG
								memory_handler(SERVER, k, TAG_LEN, &tag_up);
								if((ret = read_byte(k, (void*)tag_up, TAG_LEN)) < 0){
									error_handler("recv() [tag] failed");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}
								if(ret == 0){
									error_handler("nothing to read! 6");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}

								//	READ IV
								memory_handler(SERVER, k, IV_LEN, &iv_up);
								if((ret = read_byte(k, (void*)iv_up, IV_LEN)) < 0){
									error_handler("recv() [iv] failed");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}
								if(ret == 0){
									error_handler("nothing to read! 7");
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}

								//	DECRYPT CT
								memory_handler(SERVER, k, ct_len_up, &chunk_buf);
								ret = gcm_decrypt(ciphertext_up, ct_len_up, aad_up, aad_len_up, tag_up, session_key, iv_up, IV_LEN, chunk_buf);
								if(ret < 0){
									close(k);
									fclose(new_file);
									remove(fullpath);
									free(fullpath);
									free_var(SERVER);
									exit(0);
								}

								// WRITE BYTES TO FILE
								if(i == chunk_num - 1){ // last chunk, might be < 1MB
									if((ret = fwrite(chunk_buf, 1, size_res, new_file)) < 0){
										close(k);
										fclose(new_file);
										remove(fullpath);
										free(fullpath);
										free_var(SERVER);
										exit(0);
									}
								}
								else{
									if((ret = fwrite(chunk_buf, 1, CHUNK, new_file)) < 0){
										close(k);
										fclose(new_file);
										remove(fullpath);
										free(fullpath);
										free_var(SERVER);
										exit(0);
									}
								}
								cout << "received chunk #" << i << endl;
								free_var(SERVER);
								size_res -= CHUNK;
							}
							fclose(new_file);
							cout << "Upload ended successfully" << endl;
							free(fullpath);
							//	UPLOAD ENDED RESPONSE
							
							//	MALLOC & RAND VARIABLES
							memory_handler(SERVER, k, NONCE_LEN, &nonce_up);
							memory_handler(SERVER, k, TAG_LEN, &tag_up);
							memory_handler(SERVER, k, 1, &opcode_up);
							memory_handler(SERVER, k, IV_LEN, &iv_up);
							memory_handler(SERVER, k, 1, &plaintext_up);
							memory_handler(SERVER, k, 1, &ciphertext_up);

							plaintext_up[0] = DUMMY_BYTE;
							flag = '1';
							/*rc_up = RAND_bytes(nonce_up, NONCE_LEN);
							if(rc_up != 1){
								error_handler("nonce generation failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}*/
							rc_up = RAND_bytes(iv_up, IV_LEN);
							if(rc_up != 1){
								error_handler("iv generation failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							opcode_up[0] = '3';
							

							//	SERIALIZATION

							//	AAD SERIALIZATION
							aad_len_up = 2 + sizeof(unsigned int);	
							memory_handler(SERVER, k, aad_len_up, &aad_up);
							memory_handler(SERVER, k, sizeof(int), &aad_len_byte_up);

							serialize_int(aad_len_up, aad_len_byte_up);
							memcpy(aad_up, opcode_up, sizeof(unsigned char));
							sv_counter++;
							memcpy(&aad_up[1], &sv_counter, sizeof(unsigned int));
							memcpy(&aad_up[5], &flag, sizeof(unsigned char));
							//sv_counter++;

							//	CIPHERTEXT LEN SERIALIZATION
							ct_len_up = gcm_encrypt(plaintext_up, strlen((char*)plaintext_up), aad_up, aad_len_up, session_key, iv_up, IV_LEN, ciphertext_up, tag_up);
							if(ct_len_up <= 0){ 
								error_handler("encrypt() failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							memory_handler(SERVER, k, sizeof(int), &ct_len_byte_up);
							serialize_int(ct_len_up, ct_len_byte_up);

							//	PAYLOAD LEN SERIALIZATION
							payload_len_up = sizeof(int) + aad_len_up + sizeof(int) + ct_len_up + TAG_LEN + IV_LEN;
							memory_handler(SERVER, k, sizeof(int), &payload_len_byte_up);
							serialize_int(payload_len_up, payload_len_byte_up);

							//	BUILD MESSAGE (resp_msg)
							msg_len_up = sizeof(int) + sizeof(int) + aad_len_up + sizeof(int) + ct_len_up + TAG_LEN + IV_LEN;
							memory_handler(SERVER, k, msg_len_up, &resp_msg_up);

							memcpy(resp_msg_up, payload_len_byte_up, sizeof(int));
							memcpy((unsigned char*)&resp_msg_up[sizeof(int)], aad_len_byte_up, sizeof(int));
							memcpy((unsigned char*)&resp_msg_up[sizeof(int) + sizeof(int)], aad_up, aad_len_up);
							memcpy((unsigned char*)&resp_msg_up[sizeof(int) + sizeof(int) + aad_len_up], ct_len_byte_up, sizeof(int));
							memcpy((unsigned char*)&resp_msg_up[sizeof(int) + sizeof(int) + aad_len_up + sizeof(int)], ciphertext_up, ct_len_up);
							memcpy((unsigned char*)&resp_msg_up[sizeof(int) + sizeof(int) + aad_len_up + sizeof(int) + ct_len_up], tag_up, TAG_LEN);
							memcpy((unsigned char*)&resp_msg_up[sizeof(int) + sizeof(int) + aad_len_up + sizeof(int) + ct_len_up + TAG_LEN], iv_up, IV_LEN);

							//	SEND PACKET
							if((ret = send(k, (void*)resp_msg_up, msg_len_up, 0)) < 0){
					    			error_handler("send() failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							free_var(SERVER);
							break;
						}
						case 4:{	// dl
							unsigned char *resp_msg_dl = NULL, *opcode_dl = NULL, *nonce_dl = NULL, *ciphertext_dl = NULL, *plaintext_dl = NULL, *ct_len_byte_dl = NULL;
							unsigned char *aad_len_byte_dl = NULL, *aad_dl = NULL, *tag_dl = NULL, *iv_dl = NULL, *payload_len_byte_dl = NULL, *file_size_byte_dl = NULL;
							int ct_len_dl, aad_len_dl, msg_len_dl, rc_dl, payload_len_dl;
							
							long int file_size;					
							unsigned char flag = flag_check;
							char *fullpath;

							struct stat *s_buf;

							fullpath = (char*)calloc(MAX_PATH, sizeof(char));
							if(!fullpath){
								error_handler("malloc() [fullpath] failed, aborting");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							strncpy(fullpath, dirname, strlen(dirname));
							strncat(fullpath, (char*)plaintext, strlen((char*)plaintext));

							if(flag == '0'){	// path traversal
								memory_handler(SERVER, k, 25, &plaintext_dl);
								memory_handler(SERVER, k, 25, &ciphertext_dl);
								strncpy((char*)plaintext_dl, "Warning: path traversing", 25);
								file_size = 1;
								goto replay_dl;
							}
							else{	// Check ok, no path traversal
								if(access(fullpath, F_OK) != 0){	
									memory_handler(SERVER, k, 64, &plaintext_dl);
									memory_handler(SERVER, k, 64, &ciphertext_dl);
									flag = '0';
									strncpy((char*)plaintext_dl, "Download failed. File does not exist on server.", 48);
								}
								else{	// Check ok, file exists
									memory_handler(SERVER, k, 1, &plaintext_dl);
									memory_handler(SERVER, k, 1, &ciphertext_dl);
									plaintext_dl[0] = DUMMY_BYTE;
								}
							}
							//	FILE STAT
							s_buf = (struct stat*)malloc(sizeof(struct stat));
							if(!s_buf){
								error_handler("malloc() [buffer stat] failed");
								free(fullpath);
								free_var(SERVER);
								close(k);
								exit(0);
							}
							sv_free_buf[sv_index_free_buf] = (unsigned char*)s_buf;
							sv_index_free_buf++;

							if((stat(fullpath, s_buf)) < 0){
								error_handler("stat failed");
								free(fullpath);
								free_var(SERVER);
								close(k);
								exit(0);
							}
							file_size = s_buf->st_size;
replay_dl:
							if(file_size > 2147483647){
								memory_handler(1, k, sizeof(long int), &file_size_byte_dl);
								serialize_longint(file_size, file_size_byte_dl);
							}
							else{
								memory_handler(1, k, sizeof(int), &file_size_byte_dl);
								serialize_int(file_size, file_size_byte_dl);
							}
							
							

							//	MALLOC & RAND VARIABLES
							memory_handler(SERVER, k, NONCE_LEN, &nonce_dl);
							memory_handler(SERVER, k, TAG_LEN, &tag_dl);
							memory_handler(SERVER, k, 1, &opcode_dl);
							memory_handler(SERVER, k, IV_LEN, &iv_dl);

							/*rc_dl = RAND_bytes(nonce_dl, NONCE_LEN);
							if(rc_dl != 1){
								error_handler("nonce generation failed");
								close(k);
								free(fullpath);
								free_var(SERVER);
								exit(0);
							}*/
							rc_dl = RAND_bytes(iv, IV_LEN);
							if(rc_dl != 1){
								error_handler("iv generation failed");
								close(k);
								free(fullpath);
								free_var(SERVER);
								exit(0);
							}
							opcode_dl[0] = '4';
							

							//	SERIALIZATION

							//	AAD SERIALIZATION
							aad_len_dl = 2 + sizeof(unsigned int) + sizeof(int);
							memory_handler(SERVER, k, aad_len_dl, &aad_dl);
							memory_handler(SERVER, k, sizeof(int), &aad_len_byte_dl);

							serialize_int(aad_len_dl, aad_len_byte_dl);
							memcpy(aad_dl, opcode_dl, sizeof(unsigned char));
							sv_counter++;
							memcpy(&aad_dl[1], &sv_counter, sizeof(unsigned int));
							memcpy(&aad_dl[5], &flag, sizeof(unsigned char));
							//sv_counter++;

							if(file_size > 2147483647)
								memcpy(&aad_dl[6], &file_size, sizeof(long int));
							else
								memcpy(&aad_dl[6], &file_size, sizeof(int));

							//	CIPHERTEXT LEN SERIALIZATION
							ct_len_dl = gcm_encrypt(plaintext_dl, strlen((char*)plaintext_dl), aad_dl, aad_len_dl, session_key, iv_dl, IV_LEN, ciphertext_dl, tag_dl);
							if(ct_len_dl <= 0){ 
								error_handler("encrypt() failed");
								close(k);
								free(fullpath);
								free_var(SERVER);
								exit(0);
							}
							memory_handler(SERVER, k, sizeof(int), &ct_len_byte_dl);
							serialize_int(ct_len_dl, ct_len_byte_dl);

							//	PAYLOAD LEN SERIALIZATION
							payload_len_dl = sizeof(int) + aad_len_dl + sizeof(int) + ct_len_dl + TAG_LEN + IV_LEN;
							memory_handler(SERVER, k, sizeof(int), &payload_len_byte_dl);
							serialize_int(payload_len_dl, payload_len_byte_dl);

							//	BUILD MESSAGE (resp_msg)
							msg_len_dl = sizeof(int) + sizeof(int) + aad_len_dl + sizeof(int) + ct_len_dl + TAG_LEN + IV_LEN;
							memory_handler(SERVER, k, msg_len_dl, &resp_msg_dl);

							memcpy(resp_msg_dl, payload_len_byte_dl, sizeof(int));
							memcpy((unsigned char*)&resp_msg_dl[sizeof(int)], aad_len_byte_dl, sizeof(int));
							memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int)], aad_dl, aad_len_dl);
							memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int) + aad_len_dl], ct_len_byte_dl, sizeof(int));
							memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int) + aad_len_dl + sizeof(int)], ciphertext_dl, ct_len_dl);
							memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int) + aad_len_dl + sizeof(int) + ct_len_dl], tag_dl, TAG_LEN);
							memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int) + aad_len_dl + sizeof(int) + ct_len_dl + TAG_LEN], iv_dl, IV_LEN);

							//	SEND PACKET
							if((ret = send(k, (void*)resp_msg_dl, msg_len_dl, 0)) < 0){
					    			error_handler("send() failed");
								close(k);
								free(fullpath);
								free_var(SERVER);
								exit(0);
							}
							if(flag == '0'){
								error_handler("Error: file does not exist. Aborting operation...");
								free_var(SERVER);
								break;
							}

							// START SENDING CHUNK(S)

							//CLEAN UP
							free_var(SERVER);
							// END

							FILE *fd;
							fd = fopen(fullpath, "rb");
							if(!fd){
								error_handler("file opening failed");
								free_var(SERVER);
								free(fullpath);
								close(k);
								exit(0);
							}
							unsigned char* file_buffer = NULL;
							long int size_res = file_size;
							if(file_size > CHUNK){
								cout << "File greater than 1Mb - Proceding to send chunks" << endl;
								for(long int i = 0; i < file_size - CHUNK && file_size > CHUNK; i += CHUNK){	// If file_size is greater than 1 chunk (1mb) then send the file divided in chunk but not the last
									plaintext_dl = (unsigned char*)malloc(CHUNK);
									ciphertext_dl = (unsigned char*)malloc(CHUNK);
									if(!plaintext_dl || !ciphertext_dl){
										error_handler("malloc() failed");
										free_var(SERVER);
										close(k);
										exit(0);
									}
									file_buffer = (unsigned char*)calloc(CHUNK, sizeof(unsigned char));
									if(!file_buffer){
										error_handler("malloc() failed");
										free_var(SERVER);
										free(fullpath);
										close(k);
										exit(0);
									}
									fread(file_buffer, 1, CHUNK, fd);
									memcpy(plaintext_dl, file_buffer, CHUNK);

									//	MALLOC & RAND VARIABLES
									memory_handler(SERVER, k, NONCE_LEN, &nonce_dl);
									memory_handler(SERVER, k, TAG_LEN, &tag_dl);
									memory_handler(SERVER, k, 1, &opcode_dl);
									memory_handler(SERVER, k, IV_LEN, &iv_dl);

									/*rc_dl = RAND_bytes(nonce_dl, NONCE_LEN);
									if(rc_dl != 1){
										error_handler("nonce generation failed");
										close(k);
										free(fullpath);
										free(file_buffer);
										free_var(SERVER);
										exit(0);
									}*/
									rc_dl = RAND_bytes(iv_dl, IV_LEN);
									if(rc_dl != 1){
										error_handler("iv generation failed");
										close(k);
										free(fullpath);
										free(file_buffer);
										free_var(SERVER);
										exit(0);
									}
									opcode_dl[0] = '4';
									flag = '0';

									//	SERIALIZATION

									//	AAD SERIALIZATION
									aad_len_dl = 2 + sizeof(unsigned int);
									memory_handler(SERVER, k, aad_len_dl, &aad_dl);
									memory_handler(SERVER, k, sizeof(int), &aad_len_byte_dl);

									serialize_int(aad_len_dl, aad_len_byte_dl);
									memcpy(aad_dl, opcode_dl, sizeof(unsigned char));
									sv_counter++;
									memcpy(&aad_dl[1], &sv_counter, sizeof(unsigned int));
									memcpy(&aad_dl[5], &flag, sizeof(unsigned char));
									//sv_counter++;

									//	CIPHERTEXT LEN SERIALIZATION
									ct_len_dl = gcm_encrypt(plaintext_dl, CHUNK, aad_dl, aad_len_dl, session_key, iv_dl, IV_LEN, ciphertext_dl, tag_dl);
									if(ct_len_dl <= 0){ 
										error_handler("encrypt() failed");
										close(k);
										free(fullpath);
										free(file_buffer);
										free_var(SERVER);
										exit(0);
									}
									memory_handler(SERVER, k, sizeof(int), &ct_len_byte_dl);
									serialize_int(ct_len_dl, ct_len_byte_dl);

									//	PAYLOAD LEN SERIALIZATION
									payload_len_dl = sizeof(int) + aad_len_dl + sizeof(int) + ct_len_dl + TAG_LEN + IV_LEN;
									memory_handler(SERVER, k, sizeof(int), &payload_len_byte_dl);
									serialize_int(payload_len_dl, payload_len_byte_dl);

									//	BUILD MESSAGE (resp_msg)
									msg_len_dl = sizeof(int) + sizeof(int) + aad_len_dl + sizeof(int) + ct_len_dl + TAG_LEN + IV_LEN;
									//memory_handler(SERVER, k, msg_len_dl, &resp_msg_dl);
									resp_msg_dl = (unsigned char*)malloc(msg_len_dl);
									memcpy(resp_msg_dl, payload_len_byte_dl, sizeof(int));
									memcpy((unsigned char*)&resp_msg_dl[sizeof(int)], aad_len_byte_dl, sizeof(int));
									memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int)], aad_dl, aad_len_dl);
									memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int) + aad_len_dl], ct_len_byte_dl, sizeof(int));
									memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int) + aad_len_dl + sizeof(int)], ciphertext_dl, ct_len_dl);
									memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int) + aad_len_dl + sizeof(int) + ct_len_dl], tag_dl, TAG_LEN);
									memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int) + aad_len_dl + sizeof(int) + ct_len_dl + TAG_LEN], iv_dl, IV_LEN);

									//	SEND PACKET
									if((ret = send(k, (void*)resp_msg_dl, msg_len_dl, 0)) < 0){
							    			error_handler("send() failed");
										close(k);
										free(fullpath);
										free(file_buffer);
										free_var(SERVER);
										exit(0);
									}
									cout << "Sent chunk #" << i/CHUNK << endl;
									size_res -= CHUNK;
									free(plaintext_dl);
									free(ciphertext_dl);
									free(file_buffer);
									free(resp_msg_dl);
									free_var(SERVER);
									if(size_res < CHUNK)
										break;
								}
							}
							// send last chunk or the single chunk composing the file
							cout << "Sending last chunk" << endl;
							free_var(SERVER);
							memory_handler(SERVER, k, size_res, &plaintext_dl);
							memory_handler(SERVER, k, size_res, &ciphertext_dl);
							memory_handler(SERVER, k, size_res, &file_buffer);

							fread(file_buffer, 1, size_res, fd);
							memcpy(plaintext_dl, file_buffer, size_res);

							//	MALLOC & RAND VARIABLES
							memory_handler(SERVER, k, NONCE_LEN, &nonce_dl);
							memory_handler(SERVER, k, TAG_LEN, &tag_dl);
							memory_handler(SERVER, k, 1, &opcode_dl);
							memory_handler(SERVER, k, IV_LEN, &iv_dl);

							/*rc_dl = RAND_bytes(nonce_dl, NONCE_LEN);
							if(rc_dl != 1){
								error_handler("nonce generation failed");
								close(k);
								free(fullpath);
								free(file_buffer);
								free_var(SERVER);
								exit(0);
							}*/
							rc_dl = RAND_bytes(iv_dl, IV_LEN);
							if(rc_dl != 1){
								error_handler("iv generation failed");
								close(k);
								free(fullpath);
								free(file_buffer);
								free_var(SERVER);
								exit(0);
							}
							opcode_dl[0] = '4';
							flag = '1';

							//	SERIALIZATION

							//	AAD SERIALIZATION
							aad_len_dl = 2 + sizeof(unsigned int); 
							memory_handler(SERVER, k, aad_len_dl, &aad_dl);
							memory_handler(SERVER, k, sizeof(int), &aad_len_byte_dl);

							serialize_int(aad_len_dl, aad_len_byte_dl);
							memcpy(aad_dl, opcode_dl, sizeof(unsigned char));
							sv_counter++;
							memcpy(&aad_dl[1], &sv_counter, sizeof(unsigned int));
							memcpy(&aad_dl[5], &flag, sizeof(unsigned char));
							//sv_counter++;

							//	CIPHERTEXT LEN SERIALIZATION
							ct_len_dl = gcm_encrypt(plaintext_dl, size_res, aad_dl, aad_len_dl, session_key, iv_dl, IV_LEN, ciphertext_dl, tag_dl);
							if(ct_len_dl <= 0){ 
								error_handler("encrypt() failed");
								close(k);
								free(fullpath);
								free(file_buffer);
								free_var(SERVER);
								exit(0);
							}
							memory_handler(SERVER, k, sizeof(int), &ct_len_byte_dl);
							serialize_int(ct_len_dl, ct_len_byte_dl);
	
							//	PAYLOAD LEN SERIALIZATION
							payload_len_dl = sizeof(int) + aad_len_dl + sizeof(int) + ct_len_dl + TAG_LEN + IV_LEN;
							memory_handler(SERVER, k, sizeof(int), &payload_len_byte_dl);
							serialize_int(payload_len_dl, payload_len_byte_dl);

							//	BUILD MESSAGE (resp_msg)
							msg_len_dl = sizeof(int) + sizeof(int) + aad_len_dl + sizeof(int) + ct_len_dl + TAG_LEN + IV_LEN;
							//memory_handler(SERVER, k, msg_len_dl, &resp_msg_dl);
							resp_msg_dl = (unsigned char*)malloc(msg_len_dl);
							memcpy(resp_msg_dl, payload_len_byte_dl, sizeof(int));
							memcpy((unsigned char*)&resp_msg_dl[sizeof(int)], aad_len_byte_dl, sizeof(int));
							memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int)], aad_dl, aad_len_dl);
							memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int) + aad_len_dl], ct_len_byte_dl, sizeof(int));
							memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int) + aad_len_dl + sizeof(int)], ciphertext_dl, ct_len_dl);
							memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int) + aad_len_dl + sizeof(int) + ct_len_dl], tag_dl, TAG_LEN);
							memcpy((unsigned char*)&resp_msg_dl[sizeof(int) + sizeof(int) + aad_len_dl + sizeof(int) + ct_len_dl + TAG_LEN], iv_dl, IV_LEN);

							//	SEND PACKET
							if((ret = send(k, (void*)resp_msg_dl, msg_len_dl, 0)) < 0){
					    			error_handler("send() failed");
								close(k);
								free(fullpath);
								free(file_buffer);
								free_var(SERVER);
								exit(0);
							}
							free_var(SERVER);
							free(fullpath);
							//free(file_buffer);
							free(resp_msg_dl);
							cout << "Download completed." << endl;
							break;
						}
						case 5:{	// mv
							unsigned char *resp_msg_mv = NULL, *opcode_mv = NULL, *nonce_mv = NULL, *ciphertext_mv = NULL, *plaintext_mv = NULL, *ct_len_byte_mv = NULL;
							unsigned char *aad_len_byte_mv = NULL, *aad_mv = NULL, *tag_mv = NULL, *iv_mv = NULL, *payload_len_byte_mv = NULL;
							int ct_len_mv, aad_len_mv, msg_len_mv, rc_mv, payload_len_mv;
							DIR *dir;
							struct dirent *en;
							char *old_file_name, *new_file_name; 
							unsigned char flag = flag_check;

							old_file_name = (char*)malloc(MAX_FILE_NAME);
							if(!old_file_name){
								error_handler("malloc() failed");
								free_var(SERVER);
								exit(0);
							}
							new_file_name = (char*)malloc(MAX_FILE_NAME);
							if(!new_file_name){
								error_handler("malloc() failed");
								free_var(SERVER);
								exit(0);
							}

							if(flag == '1'){
									memory_handler(SERVER, k, 1, &plaintext_mv);
									memory_handler(SERVER, k, 1, &ciphertext_mv);
									plaintext_mv[0] = DUMMY_BYTE;
							}
							else{
								memory_handler(SERVER, k, 25, &plaintext_mv);
								memory_handler(SERVER, k, 25, &ciphertext_mv);
								strncpy((char*)plaintext_mv, "Warning: path traversing", 25);
							}
							strncpy(old_file_name, strtok((char*)plaintext, "|"), MAX_FILE_NAME);
							strncpy(new_file_name, strtok(NULL, "|"), MAX_FILE_NAME);

							dir = opendir(dirname);
			
							
							if(dir){
								char *fullpath_old, *fullpath_new;
								fullpath_old = (char*)malloc(MAX_PATH);
								if(!fullpath_old){
									error_handler("malloc() failed");
									free_var(SERVER);
									exit(0);
								}
								fullpath_new = (char*)malloc(MAX_PATH);
								if(!fullpath_new){
									error_handler("malloc() failed");
									free_var(SERVER);
									exit(0);
								}

								strncpy(fullpath_old, dirname, strlen(dirname));
								strncat(fullpath_old, old_file_name, strlen(old_file_name));				
								strncpy(fullpath_new, dirname, strlen(dirname));
								strncat(fullpath_new, new_file_name, strlen(new_file_name));
				
								while((en = readdir(dir)) != NULL){
									if(!strncmp(en->d_name, ".", strlen(".")) || !strncmp(en->d_name, "..", strlen("..")))
										continue;

									if(!strncmp(old_file_name, en->d_name, strlen(en->d_name))){ 
										if(rename((char*)fullpath_old, (char*)fullpath_new) != 0){
								       			cout << "Error: " << strerror(errno) << endl;
											flag = '0';
								   		}
										break;
									}
								}
							   	if(flag == '0')
									cout << "Rename failed. Aborting..." << endl;

							   	memory_handler(SERVER, k, NONCE_LEN, &nonce_mv);
							   	memory_handler(SERVER, k, TAG_LEN, &tag_mv);
							   	memory_handler(SERVER, k, 1, &opcode_mv);
							   	memory_handler(SERVER, k, IV_LEN, &iv_mv);
								
							   	rc_mv = RAND_bytes(nonce_mv, NONCE_LEN);
							   	if(rc_mv != 1){
							       		error_handler("nonce generation failed");
							       		close(k);
							       		free_var(SERVER);
							       		exit(0);
							   	}

							   	rc_mv = RAND_bytes(iv_mv, IV_LEN);
							   	if(rc_mv != 1){
							       		error_handler("iv generation failed");
							       		close(k);
							       		free_var(SERVER);
							       		exit(0);
							   	}

							   	opcode_mv[0] = '5';

							   	// SERIALIZATION

							   	// AAD SERIALIZATION
							   	aad_len_mv = 2 + sizeof(unsigned int);
							   	memory_handler(SERVER, k, aad_len_mv, &aad_mv);
							   	memory_handler(SERVER, k, sizeof(int), &aad_len_byte_mv);

							   	serialize_int(aad_len_mv, aad_len_byte_mv);
								memcpy(aad_mv, opcode_mv, sizeof(unsigned char));
								sv_counter++;
								memcpy(&aad_mv[1], &sv_counter, sizeof(unsigned int));
								memcpy(&aad_mv[5], &flag, sizeof(unsigned char));
								//sv_counter++;

								// CIPHERTEXT LEN SERIALIZATION
								ct_len_mv = gcm_encrypt(plaintext_mv, 1, aad_mv, aad_len_mv, session_key, iv_mv, IV_LEN, ciphertext_mv, tag_mv);
							   	if(ct_len_mv <= 0){
							       		error_handler("encrypt() failed");
							       		close(k);
							       		free_var(SERVER);
							       		exit(0);
							   	}
							   	memory_handler(SERVER, k, sizeof(int), &ct_len_byte_mv);
							   	serialize_int(ct_len_mv, ct_len_byte_mv);

								// PAYLOAD LEN SERIALIZATION
								payload_len_mv = sizeof(int) + aad_len_mv + sizeof(int) + ct_len_mv + TAG_LEN + IV_LEN;
								memory_handler(SERVER, k, sizeof(int), &payload_len_byte_mv);

								serialize_int(payload_len_mv, payload_len_byte_mv);

								// BUILD MESSAGE (resp_msg)
								msg_len_mv = sizeof(int) + sizeof(int) + aad_len_mv + sizeof(int) + ct_len_mv + TAG_LEN + IV_LEN;
							   	memory_handler(SERVER, k, msg_len_mv, &resp_msg_mv);

							   	memcpy(resp_msg_mv, payload_len_byte_mv, sizeof(int));
							   	memcpy((unsigned char*)&resp_msg_mv[sizeof(int)], aad_len_byte_mv, sizeof(int));
							   	memcpy((unsigned char*)&resp_msg_mv[sizeof(int) + sizeof(int)], aad_mv, aad_len_mv);
							   	memcpy((unsigned char*)&resp_msg_mv[sizeof(int) + sizeof(int) + aad_len_mv], ct_len_byte_mv, sizeof(int));
							   	memcpy((unsigned char*)&resp_msg_mv[sizeof(int) + sizeof(int) + aad_len_mv + sizeof(int)], ciphertext_mv, ct_len_mv);
							   	memcpy((unsigned char*)&resp_msg_mv[sizeof(int) + sizeof(int) + aad_len_mv + sizeof(int) + ct_len_mv], tag_mv, TAG_LEN);
							   	memcpy((unsigned char*)&resp_msg_mv[sizeof(int) + sizeof(int) + aad_len_mv + sizeof(int) + ct_len_mv + TAG_LEN], iv_mv, IV_LEN);

							   	// SEND PACKET
							   	if((ret = send(k, (void*)resp_msg_mv, msg_len_mv, 0)) < 0){
							       		error_handler("send() failed");
							      		close(k);
							       		free_var(SERVER);
							       		exit(0);
							   	}
							   	closedir(dir);
								free(old_file_name);
								free(new_file_name);
								free(fullpath_old);
								free(fullpath_new);
								free_var(SERVER);
						       	}	
							break;
						}
						case 6:{	// rm
							unsigned char *resp_msg_rm = NULL, *opcode_rm = NULL, *nonce_rm = NULL, *ciphertext_rm = NULL, *plaintext_rm = NULL, *ct_len_byte_rm = NULL;
							unsigned char *aad_len_byte_rm = NULL, *aad_rm = NULL, *tag_rm = NULL, *iv_rm = NULL, *payload_len_byte_rm = NULL;
							int ct_len_rm, aad_len_rm, msg_len_rm, rc_rm, payload_len_rm;

							cout << "Request for deleting: " << plaintext << endl;
						    	struct dirent *en;
							unsigned char flag = flag_check;
							DIR *dir;

							dir = opendir(dirname);
							if(dir){
								char *fullpath;

								if(flag == '1'){
									memory_handler(SERVER, k, 1, &plaintext_rm);
									memory_handler(SERVER, k, 1, &ciphertext_rm);
									plaintext_rm[0] = DUMMY_BYTE;
								}
								else{
									memory_handler(SERVER, k, 25, &plaintext_rm);
									memory_handler(SERVER, k, 25, &ciphertext_rm);
									strncpy((char*)plaintext_rm, "Warning: path traversing", 25);
									goto replay_rm;
								}
								fullpath = (char*)malloc(MAX_PATH);
								if(!fullpath){
									error_handler("malloc failed");
									close(k);
									free_var(SERVER);
									exit(0);
								}
								strncpy(fullpath, dirname, strlen(dirname));
								strncat(fullpath, (char*)plaintext, strlen((char*)plaintext) + 1);

								while((en = readdir(dir)) != NULL){
									if(!strncmp(en->d_name, ".", strlen(".")) || !strncmp(en->d_name, "..", strlen("..")))
										continue;

									if(!strncmp((char*)plaintext, en->d_name, strlen(en->d_name))){
										if(remove(fullpath) == -1){
											cout << "Error: " << strerror(errno) <<endl;
											error_handler("File not found");
											flag = '0';
										}
										else
											cout<< plaintext <<" succesfully removed"<<endl;
						                		break;
									}
								}
replay_rm:
								memory_handler(SERVER, k, NONCE_LEN, &nonce_rm);
								memory_handler(SERVER, k, TAG_LEN, &tag_rm);
								memory_handler(SERVER, k, 1, &opcode_rm);
								memory_handler(SERVER, k, IV_LEN, &iv_rm);

								rc_rm = RAND_bytes(nonce_rm, NONCE_LEN);
								if(rc_rm != 1){
									error_handler("nonce generation failed");
									close(k);
									free_var(SERVER);
									free(fullpath);
									exit(0);
								}

								rc_rm = RAND_bytes(iv_rm, IV_LEN);
								if(rc_rm != 1){
									error_handler("iv generation failed");
									close(k);
									free_var(SERVER);
									free(fullpath);
									exit(0);
								}

								opcode_rm[0] = '6';

						        	// SERIALIZATION

						        	// AAD SERIALIZATION
								aad_len_rm = 2 + sizeof(unsigned int);
								memory_handler(SERVER, k, aad_len_rm, &aad_rm);
								memory_handler(SERVER, k, sizeof(int), &aad_len_byte_rm);

								serialize_int(aad_len_rm, aad_len_byte_rm);
								memcpy(aad_rm, opcode_rm, sizeof(unsigned char));
								sv_counter++;
								memcpy(&aad_rm[1], &sv_counter, sizeof(unsigned int));
								memcpy(&aad_rm[5], &flag, sizeof(unsigned char));
								//sv_counter++;

						        	// CIPHERTEXT LEN SERIALIZATION
								ct_len_rm = gcm_encrypt(plaintext_rm, 1, aad_rm, aad_len_rm, session_key, iv_rm, IV_LEN, ciphertext_rm, tag_rm);
								if(ct_len_rm <= 0){
									error_handler("encrypt() failed");
									close(k);
									free_var(SERVER);
									free(fullpath);
									exit(0);
								}
								memory_handler(SERVER, k, sizeof(int), &ct_len_byte_rm);
								serialize_int(ct_len_rm, ct_len_byte_rm);

						        	// PAYLOAD LEN SERIALIZATION
								payload_len_rm = sizeof(int) + aad_len_rm + sizeof(int) + ct_len_rm + TAG_LEN + IV_LEN;
								memory_handler(SERVER, k, sizeof(int), &payload_len_byte_rm);

								serialize_int(payload_len_rm, payload_len_byte_rm);

						        	// BUILD MESSAGE (resp_msg)
								msg_len_rm = sizeof(int) + sizeof(int) + aad_len_rm + sizeof(int) + ct_len_rm + TAG_LEN + IV_LEN;
								memory_handler(SERVER, k, msg_len_rm, &resp_msg_rm);

								memcpy(resp_msg_rm, payload_len_byte_rm, sizeof(int));
								memcpy((unsigned char*)&resp_msg_rm[sizeof(int)], aad_len_byte_rm, sizeof(int));
								memcpy((unsigned char*)&resp_msg_rm[sizeof(int) + sizeof(int)], aad_rm, aad_len_rm);
								memcpy((unsigned char*)&resp_msg_rm[sizeof(int) + sizeof(int) + aad_len_rm], ct_len_byte_rm, sizeof(int));
								memcpy((unsigned char*)&resp_msg_rm[sizeof(int) + sizeof(int) + aad_len_rm + sizeof(int)], ciphertext_rm, ct_len_rm);
								memcpy((unsigned char*)&resp_msg_rm[sizeof(int) + sizeof(int) + aad_len_rm + sizeof(int) + ct_len_rm], tag_rm, TAG_LEN);
								memcpy((unsigned char*)&resp_msg_rm[sizeof(int) + sizeof(int) + aad_len_rm + sizeof(int) + ct_len_rm + TAG_LEN], iv_rm, IV_LEN);

						        	// SEND PACKET
								if((ret = send(k, (void*)resp_msg_rm, msg_len_rm, 0)) < 0){
									error_handler("send() failed");
									close(k);
									free_var(SERVER);
									free(fullpath);
									exit(0);
								}
								closedir(dir);
								free(fullpath);
							}
							else{
								cout << "Error: " << strerror(errno) <<endl;
								error_handler("File not found");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							free_var(SERVER);
							break;
						}
						case 7:{	// logout
							unsigned char *resp_msg_lo = NULL, *opcode_lo = NULL, *nonce_lo = NULL, *ciphertext_lo = NULL, *plaintext_lo = NULL, *ct_len_byte_lo = NULL;
							unsigned char *aad_len_byte_lo = NULL, *aad_lo = NULL, *tag_lo = NULL, *iv_lo = NULL, *payload_len_byte_lo = NULL;
							int ct_len_lo, aad_len_lo, msg_len_lo, rc_lo, payload_len_lo;
							
							//	MALLOC & RAND VARIABLES
							memory_handler(SERVER, k, 1, &plaintext_lo);
							memory_handler(SERVER, k, 1, &ciphertext_lo);
							memory_handler(SERVER, k, NONCE_LEN, &nonce_lo);
							memory_handler(SERVER, k, TAG_LEN, &tag_lo);
							memory_handler(SERVER, k, 1, &opcode_lo);
							memory_handler(SERVER, k, IV_LEN, &iv_lo);

							rc_lo = RAND_bytes(nonce_lo, NONCE_LEN);
							if(rc_lo != 1){
								error_handler("nonce generation failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}

							rc_lo = RAND_bytes(iv, IV_LEN);
							if(rc_lo != 1){
								error_handler("iv generation failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}

							opcode_lo[0] = '7';

							//	SERIALIZATION

							//	AAD SERIALIZATION
							aad_len_lo = 1 + sizeof(unsigned int);
							memory_handler(SERVER, k, aad_len_lo, &aad_lo);
							memory_handler(SERVER, k, sizeof(int), &aad_len_byte_lo);
							
							serialize_int(aad_len_lo, aad_len_byte_lo);
							sv_counter++;
							memcpy(aad_lo, opcode_lo, sizeof(unsigned char));
							memcpy(&aad_lo[1], &sv_counter, sv_counter);
							//sv_counter++;

							//	CIPHERTEXT LEN SERIALIZATION
							ct_len_lo = gcm_encrypt(plaintext_lo, 1, aad_lo, aad_len_lo, session_key, iv_lo, IV_LEN, ciphertext_lo, tag_lo);
							if(ct_len_lo <= 0){ 
								error_handler("encrypt() failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							memory_handler(SERVER, k, sizeof(int), &ct_len_byte_lo);
							serialize_int(ct_len_lo, ct_len_byte_lo);

							//	PAYLOAD LEN SERIALIZATION
							payload_len_lo = sizeof(int) + aad_len_lo + sizeof(int) + ct_len_lo + TAG_LEN + IV_LEN;
							memory_handler(SERVER, k, sizeof(int), &payload_len_byte_lo);
							
							serialize_int(payload_len_lo, payload_len_byte_lo);

							//	BUILD MESSAGE (resp_msg)
							msg_len_lo = sizeof(int) + sizeof(int) + aad_len_lo + sizeof(int) + ct_len_lo + TAG_LEN + IV_LEN;
							memory_handler(SERVER, k, msg_len_lo, &resp_msg_lo);

							memcpy(resp_msg_lo, payload_len_byte_lo, sizeof(int));
							memcpy((unsigned char*)&resp_msg_lo[sizeof(int)], aad_len_byte_lo, sizeof(int));
							memcpy((unsigned char*)&resp_msg_lo[sizeof(int) + sizeof(int)], aad_lo, aad_len_lo);
							memcpy((unsigned char*)&resp_msg_lo[sizeof(int) + sizeof(int) + aad_len_lo], ct_len_byte_lo, sizeof(int));
							memcpy((unsigned char*)&resp_msg_lo[sizeof(int) + sizeof(int) + aad_len_lo + sizeof(int)], ciphertext_lo, ct_len_lo);
							memcpy((unsigned char*)&resp_msg_lo[sizeof(int) + sizeof(int) + aad_len_lo + sizeof(int) + ct_len_lo], tag_lo, TAG_LEN);
							memcpy((unsigned char*)&resp_msg_lo[sizeof(int) + sizeof(int) + aad_len_lo + sizeof(int) + ct_len_lo + TAG_LEN], iv_lo, IV_LEN);

							//	SEND PACKET
							if((ret = send(k, (void*)resp_msg_lo, msg_len_lo, 0)) < 0){
					    			error_handler("send() failed");
								close(k);
								free_var(SERVER);
								exit(0);
							}
							// eliminare client da lista utenti
							logout(k, &list);
							memset(session_key, '\0', 32);
							free(session_key);
							free_var(SERVER);
							close(k);
							break;
						}
						default:{
							error_handler("command not found!");
							break;
						}
					}
                		}
            		}
		}
	}
	return 0;   //Unreachable code
}
