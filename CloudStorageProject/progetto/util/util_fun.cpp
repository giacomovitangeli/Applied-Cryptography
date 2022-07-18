/*		UTILITY FUNCTIONS -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

#include "data_struct.h"


using namespace std;

int cl_index_free_buf = 0;
unsigned char *cl_free_buf[1024] = {0};
int sv_index_free_buf = 0;
unsigned char *sv_free_buf[1024] = {0};
// TEST ONLY 
unsigned char key[] = "password12345678password12345678";
//	END

//	START CRYPTO UTILITY FUNCTIONS

void error_handler(const string err){
	cout << "Errore: " << err << endl;
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
    if(!(ctx = EVP_CIPHER_CTX_new())){
        error_handler("creazione contesto fallita");
	return -1;
    }

    // INIZIALIZZAZIONE CONTESTO
    if(1 != EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv)){
        error_handler("inizializzazione contesto fallita");
	return -1;
    }

    // UPDATE CONTESTO -- AAD data -> quello che voglio autenticare
    if(aad && aad_len > 0){
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){
            error_handler("update contesto (AAD) fallito");
	    return -1;
    	}
    }

    // UPDATE CONTESTO -- Generazione ciphertext
    if(1 != EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len)){
        error_handler("creazione contesto (ciphertext) fallito");
	return -1;
    }

    cipher_len = len;

    // FINALIZE
    if(1 != EVP_EncryptFinal(ctx, cipher + len, &len)){
        error_handler("final contesto fallita");
	return -1;
    }

    cipher_len += len;

    //TAG check & RET
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)){
        error_handler("autenticazione dati fallita");
	return -1;
    }

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
    if(!(ctx = EVP_CIPHER_CTX_new())){
        error_handler("creazione contesto fallita");
	return -1;
    }

    // INIZIALIZZAZIONE CONTESTO
    if(1 != EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, iv)){
        error_handler("inizializzazione contesto fallita");
	return -1;
    }

    // UPDATE CONTESTO -- AAD data -> quello che voglio autenticare
    if(aad && aad_len > 0){
        if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
            error_handler("update contesto (AAD) fallito");
	    return -1;
    	}
    }

    // UPDATE CONTESTO -- Generazione ciphertext
    if(1 != EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len)){
        error_handler("creazione contesto (ciphertext) fallito");
	return -1;
    }

    plain_len = len;

    //TAG check
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)){
        error_handler("autenticazione dati fallita");
	return -1;
    }

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
    cout<<"upload: up -[filename]"<<endl;
    cout<<"download: dl -[filename]"<<endl;
    cout<<"rename: mv -[old_filename] -[new_filename]"<<endl;
    cout<<"delete: rm -[filename]"<<endl;
    cout<<"logout: lo"<<endl;
    cout<<endl;
}

void split_file(unsigned char *cmd, unsigned char **p1, unsigned char **p2){
	char *ptr = NULL, *save = NULL;
	const char *delim = "- ";

	ptr = strtok_r((char*)cmd, delim, &save);
	if((ptr = strtok_r(NULL, delim, &save)))
		strncpy((char*)*p1, ptr, strlen(ptr));

	if((ptr = strtok_r(NULL, delim, &save)))
		strncpy((char*)*p2, ptr, strlen(ptr));

}

int whitelisting_cmd(string str) {
	string check1 = "../";
	string check2 = "..";

	if(str.find(check1) != string::npos || str.find(check2) != string::npos)
		return -1;
	return 0;
}

int check_cmd(unsigned char *plaintext, int cmd){

	char *to_check1 = NULL, *to_check2 = NULL, *pt_cpy = NULL, *free_ptr1 = NULL, *free_ptr2 = NULL;
	
	pt_cpy = (char*)calloc(strlen((char*)plaintext)+1, sizeof(char));
	to_check1 = (char*)calloc(MAX_FILE_NAME+1, sizeof(char));
	to_check2 = (char*)calloc(MAX_FILE_NAME+1, sizeof(char));

	if(!to_check1 || !to_check2 || !pt_cpy){
		error_handler("malloc() failed");
		exit(0);
	}

	free_ptr1 = to_check1;	// strtok() modify the pointer returned by calloc(), to use free a need a copy of it
	free_ptr2 = to_check2;

	strncpy(pt_cpy, (char*)plaintext, strlen((char*)plaintext));
	pt_cpy[strlen((char*)plaintext)] = '\0';
	if(cmd == 3 || cmd == 4 || cmd == 6){
		strncpy(to_check1, (char*)plaintext, strlen((char*)plaintext));

		int r = whitelisting_cmd(to_check1);

		free(to_check1);
		free(to_check2);
		return r;
	}
	else{
		if(cmd == 5) {
			to_check1 = strtok(pt_cpy, "|");
			to_check2 = strtok(NULL, "|");
			//strncpy(to_check1, strtok(pt_cpy, "|"), MAX_FILE_NAME);
			//strncpy(to_check2, strtok(NULL, "|"), MAX_FILE_NAME);

			int r1 = whitelisting_cmd(to_check1);
			int r2 = whitelisting_cmd(to_check2);

			if(r1 == 0 && r2 == 0){
				free(free_ptr1);
				free(free_ptr2);
				return 0;
			}
			else{
				free(free_ptr1);
				free(free_ptr2);
				return -1;
			}
		}
		else 
			return 0;
	}
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
	if(strncmp(cmd, "lo", 2) == 0)
		return 7;
	
	return -1;
}

void serialize_int(int val, unsigned char *c){

	c[0] =  val & 0xFF;
	c[1] = (val>>8) & 0xFF;
	c[2] = (val>>16) & 0xFF;
	c[3] = (val>>24) & 0xFF;
}

int read_byte(int sock, void *buf, ssize_t len){
	ssize_t left = len;
	int read, ret = 0;
	char *ptr = (char*)buf;
	
	while(left > 0){
		if((read = recv(sock, (void*)ptr, left, 0)) < 0)
			return -1;

		if(read == 0)
			return 0;

		left -= read;
		ptr += read;
		ret += read;
	}

	return ret;
}

int get_num_file(const char *dir_name){
	DIR *dir;
	struct dirent *en;
	int count = 0;

	dir = opendir(dir_name);
	if(dir){
		while((en = readdir(dir)) != NULL){
			if(!strcmp(en->d_name, ".") || !strcmp(en->d_name, ".."))
				continue;
				
			count++;
		}
	}
	else
		return -1;

	closedir(dir);
	return count;
}

void free_var(int side){	// Buffer allocated with malloc() pointers, multiple free()
	int counter = 0;
	if(side == 1){
		counter = cl_index_free_buf;
		for(int i = 0; i < counter - 1; i++){
			if(cl_free_buf[i]){
				free((void*)cl_free_buf[i]);
				cl_free_buf[i] = NULL;
			}
		}
		cl_index_free_buf = 0;
	}
	else if(side == 0){
		counter = sv_index_free_buf;
		for(int i = 0; i < counter - 1; i++){
			if(sv_free_buf[i]){
				free((void*)sv_free_buf[i]);
				sv_free_buf[i] = NULL;
			}
		}
		sv_index_free_buf = 0;
	}
	else{
		cerr << "Panic! Critical error, shutting down program..." << endl;
		exit(0);
	}	
}

void memory_handler(int side, int socket, int new_size, unsigned char **new_buf){
	*new_buf = (unsigned char*)calloc(new_size+1, sizeof(unsigned char*));
	if(!*new_buf){
		free_var(side);
		if(socket)
			close(socket);

		cerr << "Critical error: malloc() failed allocating " << new_size << " new bytes" << endl << "Exit program" << endl;
		exit(0);
	}

	if(side == 1){
		cl_free_buf[cl_index_free_buf] = *new_buf;
		cl_index_free_buf++;
	}
	else if(side == 0){
		sv_free_buf[sv_index_free_buf] = *new_buf;
		sv_index_free_buf++;
	}
	else{
		cerr << "Panic! Critical error, shutting down program..." << endl;
		if(socket)
			close(socket);
		free_var(0);
		free_var(1);
		exit(0);
	}	
}

/*int c_authenticate(int sock, user **usr){	// auth client side - send nonce + username - receive crypto data - send session key (& other crypto data)
	// USERNAME SELECTION & STRUCT INITIALIZATION
	string username = "";
	cout << "Please enter your username. (MAX 10 characters)" << endl;
	cin >> username;
	if(username.size() == 0 || username.size() > 10){
		cout << "Invalid username" << endl;
		return -1;
	}

	(*usr) = new user;
	strncpy((*usr)->username, username.c_str(), username.size());
	(*usr)->username[username.size()] = '\0';
	(*usr)->u_socket = sock;

	// SEND NONCE + USERNAME
	int pay_len = 0;
	unsigned char *nonce = NULL, *paylen_byte, *msg;
	memory_handler(1, sock, NONCE_LEN, &nonce);
	random_byte(NONCE_LEN, &nonce);

	pay_len = NONCE_LEN + username.size();
	memory_handler(1, sock, pay_len, &paylen_byte);
	serialize_int(pay_len, paylen_byte);

	int m_len = sizeof(int) + NONCE_LEN + username.size();
	memory_handler(1, sock, m_len, &msg);

	memcpy(msg, paylen_byte, sizeof(int));
	memcpy((unsigned char*)&msg[sizeof(int)], nonce, NONCE_LEN);
	memcpy((unsigned char*)&msg[sizeof(int) + NONCE_LEN], username.c_str(), username.size());

	int ret;
	if((ret = send(sock, (void*)msg, m_len, 0)) <= 0){
		free_var(1);
		return -1;
	}
	
	// RECEIVE SERVER REPLAY

	





	return 1;	
}

int s_authenticate(int sock, user **usr_list){	// auth server side - receive nonce + username - send crypto data - receive session key (& other crypto data)

}*/
//	END UTILITY FUNCTIONS





