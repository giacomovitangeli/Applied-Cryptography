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

int digital_sign(EVP_PKEY *private_key, unsigned char *to_sign, int to_sign_len, unsigned char *sign_buf){
	EVP_MD* md = EVP_sha256();
	int ret = -1;
	int sign_len = 0;

	// CONTEST CREATION
	EVP_MD_CTX* ctx;
	if(!(ctx = EVP_MD_CTX_new())){
        	error_handler("Digital Signature contest creation failed");
		return -1;
    	}

	// CONTEST INITIALIZATION
	if((ret = EVP_SignInit(ctx, md)) != 1){
		error_handler("Digital Signature contest initialization failed");
		return -1;
	}
	
	// CONTEST UPDATE
	if((ret = EVP_SignUpdate(ctx, to_sign, to_sign_len)) != 1){
		error_handler("Digital Signature contest update failed");
		return -1;
	}

	// CONTEST FINAL
	if((ret = EVP_SignFinal(ctx, sign_buf, &sign_len, private_key)) != 1){
		error_handler("Digital Signature contest final failed");
		return -1;
	}
	
	// FREE CONTEXT
	EVP_MD_CTX_free(ctx);

	return sign_len;
}

int digital_sign_verify(EVP_PKEY *public_key, unsigned char *sign_buf, int sign_len, unsigned char *to_verify, int to_verify_len){
	EVP_MD* md = EVP_sha256();
	int ret = -1;

	// CONTEST CREATION
	EVP_MD_CTX* ctx;
	if(!(ctx = EVP_MD_CTX_new())){
        	error_handler("Digital Signature contest creation failed");
		return -1;
    	}
	
	// CONTEST INITIALIZATION
	if((ret = EVP_VerifyInit(ctx, md)) != 1){
		error_handler("Digital Signature contest initialization failed");
		return -1;
	}
	
	// CONTEST UPDATE
	if((ret = EVP_VerifyUpdate(ctx, to_verify, to_verify_len)) != 1){
		error_handler("Digital Signature contest update failed");
		return -1;
	}

	// CONTEST FINAL
	ret = EVP_VerifyFinal(ctx, sign_buf, sign_len, public_key);

	// FREE CONTEXT
	EVP_MD_CTX_free(ctx);

	return ret;
}

int certificate_validation(string CA_path, string CA_CRL_path, X509 *sv_cert){

	int ret = 0;

	// CA certificate file
	FILE* CA_sv_cert_fd = fopen(CA_path.c_str(), "r");
	if(!CA_sv_cert_fd){
		error_handler("Failed to open CA cert file");
		return -1;
	}

	// Reading CA certificate
	X509* CA_cert = PEM_read_X509(CA_sv_cert_fd, NULL, NULL, NULL);
	fclose(CA_sv_cert_fd);
	if(!CA_cert){
		error_handler("PEM_read() failed");
		return -1;
	}

	// CRL file
	FILE* CRL_fd = fopen(CA_CRL_path.c_str(), "r");
	if(!CRL_fd){
		error_handler("Failed to open CA CRL file");
		return -1;
	}

	// Reading CRL
	X509_CRL *crl = PEM_read_X509_CRL(CRL_fd, NULL, NULL, NULL);
	fclose(CRL_fd);
	if(!crl){
		error_handler("PEM_read_crl() failed");
		return -1;
	}

	// Build store
	X509_STORE *store = X509_STORE_new();
	if(!store){
		error_handler("X509_store_new() failed");
		return -1;
	}

	// Adding CA
	ret = X509_STORE_add_cert(store, CA_cert);
	if(ret != 1){
		error_handler("add_cert() failed");
		return -1;
	}

	// Adding CRL
	ret = X509_STORE_add_crl(store, crl);
	if(ret != 1){
		error_handler("add_crl() failed");
		return -1;
	}

	// Setting flag
	ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
	if(ret != 1){
		error_handler("set_flag() failed");
		return -1;
	}

	// Contest for verification
	X509_STORE_CTX *cert_verify_ctx = X509_STORE_CTX_new();
	if(!cert_verify_ctx){
		error_handler("store_ctx_new() failed");
		return -1;
	}

	// Initialize context
	ret = X509_STORE_CTX_init(cert_verify_ctx, store, sv_cert, NULL);
	if(ret != 1){
		error_handler("store_ctx_init() failed");
		return -1;
	}

	// Verify certificate
	ret = X509_verify_cert(cert_verify_ctx);
	if(ret != 1) {
		error_handler("X509_verify_cert fails!");
		return -1;
	}

	return 1;
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

//	COMMAND FUNCTIONS

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

//	MEMORY FUNCTIONS

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

//	SERIALIZATION & KEY CAST

void serialize_int(int val, unsigned char *c){
	c[0] =  val & 0xFF;
	c[1] = (val>>8) & 0xFF;
	c[2] = (val>>16) & 0xFF;
	c[3] = (val>>24) & 0xFF;
}

int serialize_certificate(string path, unsigned char *buf){

	// Reading cert
	FILE* cert_fd = fopen(path.c_str(), "r");
	if(!cert_fd){
		error_handler("failed to open certificate file");
		return -1;
	}

	X509* cert = PEM_read_X509(cert_fd, NULL, NULL, NULL);
	if(!cert){
		error_handler("failed to read certificate");
		return -1;
	}
	fclose(cert_fd);

	// Memory bio setup
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, cert); // Write server_cert into bio

	// Serialize the certificate
	int buf_size = BIO_get_mem_data(bio, &buf);
	if(buf_size < 0)
		return -1;

	return 1;
}

void deserialize_certificate(X509 **cert, unsigned char* cert_buff, int cert_size){
	BIO* bio = BIO_new(BIO_s_mem());
	BIO_write(bio, cert_buff, cert_size);

	*cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

	BIO_free(bio);
}

void pubkey_to_PKEY(EVP_PKEY **pub_key, unsigned char *public_key, int len){

	BIO* mbio = BIO_new(BIO_s_mem());
	BIO_write(mbio, public_key, len);

	*pub_key =  PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
	BIO_free(mbio);
}

void privkey_to_PKEY(EVP_PKEY **priv_key, unsigned char *private_key, int len){

	BIO* mbio = BIO_new(BIO_s_mem());
	BIO_write(mbio, private_key, len);

	*priv_key =  PEM_read_bio_PrivateKey(mbio, NULL, NULL, NULL);
	BIO_free(mbio);
}

void serialize_pubkey(EVP_PKEY *public_key, int *pub_key_len, unsigned char **pkey){

	BIO *bio = NULL;
	int key_len = 0;

	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(bio, public_key);

	key_len = BIO_pending(bio);
	*pub_key_len = key_len;

	*pkey = (unsigned char*)calloc(sizeof(unsigned char) * key_len, sizeof(unsigned char));
	if(!*pkey){
		error_handler("malloc() failed");
		exit(0);
	}
	BIO_read(bio, *pkey, key_len);
	BIO_free_all(bio);
}

//	LIST FUNCTIONS

void get_user_fullpath(char **fullpath, char *basepath, user *list, int sv_sock){
	
}

//	AUTHENTICATION FUNCTIONS

int c_authenticate(int sock, user **usr){	// auth client side - send nonce + username - receive crypto data - send session key (& other crypto data)
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
	(*usr)->u_cl_socket = sock;
	(*usr)->u_sv_socket = 0;
	(*usr)->next = NULL;

	// SEND NONCE + USERNAME
	int pay_len = 0, rc = 0;
	unsigned char *nonce = NULL, *paylen_byte, *msg;
	memory_handler(1, sock, NONCE_LEN, &nonce);
	rc = RAND_bytes(nonce, NONCE_LEN);
	if(rc != 1){
		error_handler("nonce generation failed");
		free_var(CLIENT);
		close(socket_d);
		exit(0);
	}

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
		free_var(CLIENT);
		return -1;
	}
	
	// RECEIVE SERVER REPLAY

	int payload_len, ct_len, sign_len, key_eph_len, cert_buf_len;						// DIMENSIONI INT
    	unsigned char *sign_buf, *key_eph_buf, *cert_buf;							// BUFFER
	unsigned char *payload_len_byte, *ct_len_byte, *sign_len_byte, *key_eph_len_byte, *cert_buf_len_byte;	// DIMENSIONI BYTE
	X509 *cert = NULL;

	//	READ PAYLOAD_LEN
	memory_handler(CLIENT, socket_d, sizeof(int), &payload_len_byte);
	if((ret = read_byte(socket_d, (void*)payload_len_byte, sizeof(int))) < 0){
		error_handler("recv() [rcv_msg] failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 1");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	memcpy(&payload_len, payload_len_byte, sizeof(int));

	//	READ SIGN_LEN & SIGN			
	memory_handler(CLIENT, sock, sizeof(int), &sign_len_byte);
	if((ret = read_byte(sock, (void*)sign_len_byte, sizeof(int))) < 0){
		error_handler("recv() [sign_len_byte] failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 2");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	memcpy(&sign_len, sign_len_byte, sizeof(int));
	memory_handler(CLIENT, sock, sign_len, &sign_buf);
	if((ret = read_byte(sock, (void*)sign_buf, sign_len)) < 0){
		error_handler("recv() [sign_buf] failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 3");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}

	//	READ KEY_EPH_LEN & KEY_EPH		
	memory_handler(CLIENT, sock, sizeof(int), &key_eph_len_byte);
	if((ret = read_byte(sock, (void*)key_eph_len_byte, sizeof(int))) < 0){
		error_handler("recv() [sign_len_byte] failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 2");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	memcpy(&key_eph_len, key_eph_len_byte, sizeof(int));
	memory_handler(CLIENT, sock, key_eph_len, &key_eph_buf);
	if((ret = read_byte(sock, (void*)key_eph_buf, key_eph_len)) < 0){
		error_handler("recv() [key_eph_buf] failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 3");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}

	//	READ CERT_BUF_LEN & CERT_BUF		
	memory_handler(CLIENT, sock, sizeof(int), &cert_buf_len_byte);
	if((ret = read_byte(sock, (void*)cert_buf_len_byte, sizeof(int))) < 0){
		error_handler("recv() [cert_buf_len_byte] failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 2");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	memcpy(&cert_buf_len, cert_buf_len_byte, sizeof(int));
	memory_handler(CLIENT, sock, cert_buf_len, &cert_buf);
	if((ret = read_byte(sock, (void*)cert_buf, cert_buf_len)) < 0){
		error_handler("recv() [cert_buf] failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 3");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}

	return 1;	
}

int s_authenticate(int sock, user **usr_list){	// auth server side - receive nonce + username - send crypto data - receive session key (& other crypto data)

}
//	END UTILITY FUNCTIONS





