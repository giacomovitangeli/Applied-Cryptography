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

int envelope_encrypt(EVP_PKEY* public_key, unsigned char* plaintext, int pt_len, unsigned char* sym_key_enc, int sym_key_len, unsigned char* iv, unsigned char* ciphertext){

	int ret = 0;
	int outlen = 0;
	int ct_len = 0;

	// Create and initialise the context 
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx){
		error_handler("creazione contesto fallita");
		return -1;
	}

	// Generate the IV and the symmetric key and encrypt the symmetric key 
	ret = EVP_SealInit(ctx, EVP_aes_256_cbc(), &sym_key_enc, &sym_key_len, iv, &public_key, 1);
	if(ret != 1){
		error_handler("seal init contesto fallito");
	    	return -1;
	}

	// Encrypt the plaintext 
	ret = EVP_SealUpdate(ctx, ciphertext, &outlen, (unsigned char*)plaintext, pt_len);
	if(ret != 1){
		error_handler("seal update contesto fallito");
	    	return -1;
	}
	ct_len = outlen;

	// Finalize the encryption and add the padding
	ret = EVP_SealFinal(ctx, ciphertext + ct_len, &outlen);
	if(ret != 1){
		error_handler("seal final contesto fallito");
	    	return -1;
	}
	ct_len += outlen;

	EVP_CIPHER_CTX_free(ctx);

	return ct_len;
}

int envelope_decrypt(EVP_PKEY* private_key, unsigned char* ciphertext, int ct_len, unsigned char* sym_key_enc, int sym_key_len, unsigned char* iv, unsigned char* plaintext){

	int ret = 0;
	int outlen = 0;
	int pt_len = 0;

	// Create and initialise the context 
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx){
		error_handler("creazione contesto fallita");
		return -1;
	}

	// Decrypt the symmetric key that will be used to decrypt the ciphertext 
	ret = EVP_OpenInit(ctx, EVP_aes_256_cbc(), sym_key_enc, sym_key_len, iv, private_key);
	if(ret != 1){
		error_handler("open init contesto fallito");
	    	return -1;
	}

	// Decrypt the ciphertext 
	ret = EVP_OpenUpdate(ctx, plaintext, &outlen, ciphertext, ct_len);
	if(ret != 1){
		error_handler("open update contesto fallito");
	    	return -1;
	}
	pt_len += outlen;

	ret = EVP_OpenFinal(ctx, plaintext + pt_len, &outlen);
	if(ret != 1){
		error_handler("open final contesto fallito");
	    	return -1;
	}

	pt_len += outlen;
	EVP_CIPHER_CTX_free(ctx);

	return pt_len;
}

int digital_sign(EVP_PKEY *private_key, unsigned char *to_sign, int to_sign_len, unsigned char *sign_buf){
	const EVP_MD* md = EVP_sha256();
	int ret = -1;
	unsigned int sign_len = 0;

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
	cout << "Sign Len: " << sign_len << endl;
	return sign_len;
}

int digital_sign_verify(EVP_PKEY *public_key, unsigned char *sign_buf, int sign_len, unsigned char *to_verify, int to_verify_len){ //unsigned int
	const EVP_MD* md = EVP_sha256();
	int ret = -1;

	cout << "Sign Len: " << sign_len << endl;
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
	if((ret = EVP_VerifyFinal(ctx, sign_buf, sign_len, public_key)) != 1){
		cout << ERR_error_string(ERR_get_error(),NULL) << endl;
		return -1;
	}
	// FREE CONTEXT
	EVP_MD_CTX_free(ctx);
	cout << "Sign verified successfully" << endl;
	return ret;
}

int certificate_validation(string CA_path, string CA_CRL_path, X509 *sv_cert){

	int ret = -1;

	// CA certificate file
	FILE* CA_sv_cert_fd = fopen(CA_path.c_str(), "r");
	if(!CA_sv_cert_fd){
		error_handler("Failed to open CA cert file");
		return -1;
	}

	// Reading CA certificate
	X509* CA_cert = PEM_read_X509(CA_sv_cert_fd, NULL, NULL, NULL);
	//print_Server_cert_info(CA_cert);
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
		//cout << "Errore ret: " << ret << endl;
		//print_Server_cert_info(sv_cert);
		cout << X509_verify_cert_error_string(X509_STORE_CTX_get_error(cert_verify_ctx)) << endl;
		error_handler("X509_verify_cert fails!");
		return -1;
	}
	cout << "Certificate is valid!" << endl;
	return 1;
}

void eph_keys_gen(EVP_PKEY** k_priv, EVP_PKEY** k_pub){

	RSA *rsa = NULL;
	BIGNUM* big_num = NULL;
	BIO *bio = NULL;
	BIO *bio_pub = NULL;


	// Generate RSA key
	big_num = BN_new();
	BN_set_word(big_num, RSA_F4);
	rsa = RSA_new();
	RSA_generate_key_ex(rsa, 2048, big_num, NULL);
	BN_free(big_num);


	// Extract the private key
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
	PEM_read_bio_PrivateKey(bio, &(*k_priv), NULL, NULL);
	BIO_free_all(bio);


	// Extract the public key
	bio_pub = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(bio_pub, *k_priv);
	PEM_read_bio_PUBKEY(bio_pub, &(*k_pub), NULL, NULL);
	BIO_free_all(bio_pub);

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

unsigned char* serialize_certificate(string path, int *cert_len){

	// Reading certificate from file
	//cout << "Cert path to open: " << path.c_str() << endl;
	FILE* fd_cert = fopen(path.c_str(), "r");
	if(!fd_cert){
		cout << "fopen fail" << endl;
		return NULL;
	}

	X509* cert = PEM_read_X509(fd_cert, NULL, NULL, NULL);
	if(!cert){
		cout << "pem read fail" << endl;
		return NULL;
	}
	fclose(fd_cert);

	// Memory bio
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, cert);


	// Serialize the certificate
	unsigned char* buf_cert = NULL;
	*cert_len = BIO_get_mem_data(bio, &buf_cert);
	if((*cert_len) < 0)
		return NULL;
	//cout << "serialized certificate: " << buf_cert << endl;
	return buf_cert;
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

int serialize_pubkey(EVP_PKEY *public_key, unsigned char **pkey){

	BIO *bio = NULL;
	int key_len = 0;

	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(bio, public_key);

	key_len = BIO_pending(bio);

	*pkey = (unsigned char*)calloc(sizeof(unsigned char) * key_len, sizeof(unsigned char));
	if(!*pkey){
		error_handler("malloc() failed");
		exit(0);
	}
	BIO_read(bio, *pkey, key_len);
	BIO_free_all(bio);
	return key_len;
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

	// SEND NONCE + USERNAME	[pay len][nonce][username]
	int pay_len = 0, rc = 0;
	unsigned char *nonce = NULL, *paylen_byte, *msg;
	memory_handler(1, sock, NONCE_LEN, &nonce);
	rc = RAND_bytes(nonce, NONCE_LEN);
	if(rc != 1){
		error_handler("nonce generation failed");
		free_var(CLIENT);
		close(sock);
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
	
	// RECEIVE SERVER REPLAY	[pay_len][sign len][sign][eph key len][eph key][cert len][cert]

	int payload_len, ct_len, sign_len, key_eph_len, cert_buf_len, sign_verify_len, session_key_len;			// DIMENSIONI INT
    	unsigned char *sign_buf, *key_eph_buf, *cert_buf, *sign_verify_buf, *session_key;				// BUFFER
	unsigned char *payload_len_byte, *sign_len_byte, *key_eph_len_byte, *cert_buf_len_byte;				// DIMENSIONI BYTE
	EVP_PKEY *pubK_sv = NULL, *privK_cl = NULL;
	X509 *cert = NULL;

	//	READ PAYLOAD_LEN
	memory_handler(CLIENT, sock, sizeof(int), &payload_len_byte);
	if((ret = read_byte(sock, (void*)payload_len_byte, sizeof(int))) < 0){
		error_handler("recv() [rcv_msg] failed 2");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 10");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	memcpy(&payload_len, payload_len_byte, sizeof(int));
	//cout << "pay len: " << payload_len << endl;
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
	//cout << "Sign len: " << sign_len << endl;
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
	//cout << "Sign buf: " << endl << sign_buf << endl;
	//	READ KEY_EPH_LEN & KEY_EPH		
	memory_handler(CLIENT, sock, sizeof(int), &key_eph_len_byte);
	if((ret = read_byte(sock, (void*)key_eph_len_byte, sizeof(int))) < 0){
		error_handler("recv() [sign_len_byte] failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 20");
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
	
	//cout << "Key eph: " << key_eph_buf << endl;
	if(ret == 0){
		error_handler("nothing to read! 30");
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
		error_handler("nothing to read! 21");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	memcpy(&cert_buf_len, cert_buf_len_byte, sizeof(int));
	//cout << "cert buf len: " << cert_buf_len << endl;
	memory_handler(CLIENT, sock, cert_buf_len, &cert_buf);
	if((ret = read_byte(sock, (void*)cert_buf, cert_buf_len)) < 0){
		error_handler("recv() [cert_buf] failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 31");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	//cout << "recived certificate buf: " << endl << cert_buf << endl;
	//	EXTRACT PUBLIC KEY FROM CERT
	char *abs_path;
	abs_path = (char*)malloc(MAX_PATH);
	getcwd(abs_path, MAX_PATH);

	string pem_path = strcat(abs_path, "/client_src/CA/CA_cert.pem");
	getcwd(abs_path, MAX_PATH);

	string crl_path = strcat(abs_path, "/client_src/CA/CA_crl.pem");
	//string CA_path = CA_path_folder + pem_path;

	//cout << "pem path: " << pem_path << endl;
	//string CA_CRL_path = CA_path_folder + crl_path;
	deserialize_certificate(&cert, cert_buf, cert_buf_len);
	ret = certificate_validation(pem_path, crl_path, cert);
	if(ret != 1){
		error_handler("Certificate validation failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}

	pubK_sv = X509_get_pubkey(cert);
	if(!pubK_sv){
		error_handler("PubKey extraction failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	//cout << "pub key extracted: " << endl;
	//PEM_write_PUBKEY(stdout, pubK_sv);
	//	SIGN VERIFICATION	<nonce||key_pub_eph>
	sign_verify_len = NONCE_LEN + key_eph_len;	//2x
	memory_handler(CLIENT, sock, sign_verify_len, &sign_verify_buf);
	//memcpy(nonce, "1234567890123456", NONCE_LEN);
	memcpy(sign_verify_buf, nonce, NONCE_LEN);	//NONCE_LEN
	memcpy((unsigned char*)&sign_verify_buf[NONCE_LEN], key_eph_buf, key_eph_len);
	//cout << "Sign to verify: " << endl << sign_verify_buf << endl;
	ret = digital_sign_verify(pubK_sv, sign_buf, (unsigned int)sign_len, sign_verify_buf, (unsigned int)sign_verify_len); //(unsigned int)
	if(ret != 1){
		error_handler("Sign not valid 1");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}


	//	SEND SESSION KEY TO SERVER	[pay len][sign len][sign][ciph len][ciphertext][len cripted key][cripted key][iv]

	int sign_len_r, s_key_enc_len, resp_msg_len, aad_len;					// DIMENSIONI INT
    	unsigned char *s_key_enc, *iv, *ciphertext, *resp_msg;		// BUFFER
	unsigned char *sign_len_byte_r, *s_key_enc_len_byte, *ct_len_byte, *aad_len_byte;				// DIMENSIONI BYTE
	unsigned char *to_sign, *buf_signed, *aad;
	EVP_PKEY *eph_key = NULL;

	//	READ PRIV KEY FROM PEM FILE
	getcwd(abs_path, MAX_PATH);
	string key_path = "/client_src/keys/" + username + "_private_key.pem";
	string priv_key = strcat(abs_path, key_path.c_str());
	
	FILE *pem_fd = fopen(priv_key.c_str(), "r");
	if(!pem_fd){
		error_handler("Can't open PEM file");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	privK_cl = PEM_read_PrivateKey(pem_fd, NULL, NULL, NULL);

	session_key_len =  EVP_CIPHER_key_length(EVP_aes_256_gcm());
	
	//s_key_enc_len = EVP_PKEY_size(eph_key); // errore

	memory_handler(CLIENT, sock, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), &iv);
	memory_handler(CLIENT, sock, 64, &ciphertext);
	memory_handler(CLIENT, sock, session_key_len, &session_key);
	memory_handler(CLIENT, sock, s_key_enc_len, &s_key_enc);
	
	ret = RAND_bytes(session_key, session_key_len);
	pubkey_to_PKEY(&eph_key, key_eph_buf, key_eph_len);
	ct_len = envelope_encrypt(eph_key, session_key, session_key_len, s_key_enc, s_key_enc_len, iv, ciphertext);	
	sign_len_r = key_eph_len + ct_len;

	// SIGN INITIALIZATION

	memory_handler(CLIENT, sock, sign_len_r, &to_sign);
	memory_handler(CLIENT, sock, sign_len_r, &buf_signed);
	memory_handler(CLIENT, sock, sizeof(int), &sign_len_byte_r);
	memory_handler(CLIENT, sock, sizeof(int), &ct_len_byte);
	memory_handler(CLIENT, sock, sizeof(int), &aad_len_byte);
	memory_handler(CLIENT, sock, sizeof(int), &s_key_enc_len_byte);

	memcpy(to_sign, ciphertext, ct_len);
	memcpy(&to_sign[ct_len], key_eph_buf, key_eph_len);

	ret = digital_sign(privK_cl, to_sign, sign_len_r, buf_signed);
	if(ret < 0){
		error_handler("Sign error");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}

	serialize_int(sign_len_r, sign_len_byte_r);
	serialize_int(ct_len, ct_len_byte);
	serialize_int(s_key_enc_len, s_key_enc_len_byte);

	// [pay len][sign len][sign][ciph len][ciphertext][len cripted key][cripted key][iv]
	aad_len = sizeof(int) + sizeof(int) + sign_len_r + sizeof(int) + ct_len + sizeof(int) + s_key_enc_len + EVP_CIPHER_iv_length(EVP_aes_256_cbc());
	serialize_int(aad_len, aad_len_byte);

	memory_handler(CLIENT, sock, aad_len, &aad);
	memcpy((unsigned char*)aad, aad_len_byte, sizeof(int));
	memcpy((unsigned char*)&aad[sizeof(int)], sign_len_byte_r, sizeof(int)); 
	memcpy((unsigned char*)&aad[sizeof(int) + sizeof(int)], buf_signed, sign_len_r);
	memcpy((unsigned char*)&aad[sizeof(int) + sizeof(int) + sign_len_r], ct_len_byte, sizeof(int));
	memcpy((unsigned char*)&aad[sizeof(int) + sizeof(int) + sign_len_r + sizeof(int)], ciphertext, ct_len);
	memcpy((unsigned char*)&aad[sizeof(int) + sizeof(int) + sign_len_r + sizeof(int) + ct_len], s_key_enc_len_byte, sizeof(int));
	memcpy((unsigned char*)&aad[sizeof(int) + sizeof(int) + sign_len_r + sizeof(int) + ct_len + sizeof(int)], s_key_enc, s_key_enc_len);
	memcpy((unsigned char*)&aad[sizeof(int) + sizeof(int) + sign_len_r + sizeof(int) + ct_len + sizeof(int) + s_key_enc_len], iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc()));

	// SYMMETRIC ENCRYPTION

	unsigned char *cipher, *tag, *iv2;
	
	memory_handler(CLIENT, sock, session_key_len, &cipher);
	memory_handler(CLIENT, sock, TAG_LEN, &tag);
	memory_handler(CLIENT, sock, IV_LEN, &iv2);
	ct_len = gcm_encrypt(session_key, session_key_len, aad, aad_len, key_eph_buf, iv2, IV_LEN, cipher, tag);
	if(ct_len < 0){
		error_handler("Encryption symkey failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}

	// SEND MSG

	resp_msg_len = aad_len + ct_len + TAG_LEN + IV_LEN;
	memory_handler(CLIENT, sock, resp_msg_len, &resp_msg);
	
	memcpy((unsigned char*)resp_msg, aad, aad_len); 
	memcpy((unsigned char*)&resp_msg[aad_len], cipher, ct_len);
	memcpy((unsigned char*)&resp_msg[aad_len + ct_len], tag, TAG_LEN);
	memcpy((unsigned char*)&resp_msg[aad_len + ct_len + TAG_LEN], iv, IV_LEN);

	if((ret = send(sock, (void*)resp_msg, resp_msg_len, 0)) < 0){
		error_handler("send() failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}

	return 1;	
}

int s_authenticate(int sock, user **usr_list){	// auth server side - receive nonce + username - send crypto data - receive session key (& other crypto data)

	int payload_len, user_len, ret;
	unsigned char *user, *nonce;
	unsigned char *payload_len_byte;
	char *abs_path;

	abs_path = (char*)malloc(MAX_PATH);
	getcwd(abs_path, MAX_PATH);
	
	//	READ PAYLOAD_LEN
	memory_handler(SERVER, sock, sizeof(int), &payload_len_byte);
	if((ret = read_byte(sock, (void*)payload_len_byte, sizeof(int))) < 0){
		error_handler("recv() failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 10");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	memcpy(&payload_len, payload_len_byte, sizeof(int));

	//	READ USER & NONCE
	user_len = payload_len - NONCE_LEN;

	memory_handler(SERVER, sock, user_len, &user);
	memory_handler(SERVER, sock, NONCE_LEN, &nonce);

	if((ret = read_byte(sock, (void*)nonce, NONCE_LEN)) < 0){
		error_handler("recv() failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 11");
		free_var(SERVER);
		close(sock);
		exit(0);
	}

	if((ret = read_byte(sock, (void*)user, user_len)) < 0){
		error_handler("recv() failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 12");
		free_var(SERVER);
		close(sock);
		exit(0);
	}

	//	CHECK USERNAME
	//string curdir = "/server_src/";
	string username(reinterpret_cast<char*>(user));
	string dir_name = strcat(abs_path, "/server_src/");

	DIR *dir;
	struct dirent *en;
	int check = 0;
	dir = opendir(dir_name.c_str());
	if(dir){
		while((en = readdir(dir)) != NULL){
			//cout << en->d_name << endl;
			if(!strcmp(en->d_name, username.c_str()))
				check = 1;	
		}
	}
	closedir(dir);
	if(check == 0){
		error_handler("Username not found...");
		free_var(SERVER);
		close(sock);
		exit(0);
	}

	//	SEND REPLAY WITH CRYPTO INFO	[pay_len][sign len][sign][eph key len][eph key][cert len][cert]
	int sign_len, key_len, cert_len;
	unsigned char *to_sign, *sign_buf, *eph_pub_key, *session_key;
	unsigned char *sign_len_byte, *key_len_byte, *cert_len_byte;
	EVP_PKEY *eph_key_priv = NULL, *eph_key_pub = NULL, *privK_sv = NULL;

	//	GETTING PRIV KEY
	getcwd(abs_path, MAX_PATH);
	string key_path = strcat(abs_path, "/server_src/cert/serverpriv.pem");
	//cout << "PEM Path: " << key_path.c_str() << endl;
	FILE *pem_fd = fopen(key_path.c_str(), "r");
	if(!pem_fd){
		error_handler("Can't open PEM file 999");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	privK_sv = PEM_read_PrivateKey(pem_fd, NULL, NULL, NULL);
	//cout << "priv key extracted: " << endl;
	//cout << "PrivRSAKey: " << endl;
	//PEM_write_PrivateKey(stdout, privK_sv, NULL, NULL, NULL, NULL, NULL);
	cout << endl;
	//	GENERATE EPH KEYS
	eph_keys_gen(&eph_key_priv, &eph_key_pub);
	if(!eph_key_priv || !eph_key_pub){
		error_handler("Error generating RSA Eph Keys");
		free_var(SERVER);
		close(sock);
		exit(0);
	}

	//cout << "eph keys: " << eph_key_priv << "     " << eph_key_pub << endl;
	//	SIGN
	key_len = EVP_PKEY_size(eph_key_pub);
	
	memory_handler(SERVER, sock, sizeof(int), &key_len_byte);
	//serialize_int(key_len, key_len_byte);

	memory_handler(SERVER, sock, key_len, &eph_pub_key);
	sign_len = key_len + NONCE_LEN;
	serialize_pubkey(eph_key_pub, &eph_pub_key);
	serialize_int(key_len, key_len_byte);
	memory_handler(SERVER, sock, sign_len, &to_sign);
	memory_handler(SERVER, sock, sizeof(int), &sign_len_byte);
	//memcpy(nonce , "1234567890123456", NONCE_LEN);
	memcpy(&to_sign[0], nonce, NONCE_LEN);	//NONCE_LEN
	memcpy(&to_sign[NONCE_LEN], eph_pub_key, key_len);
	//cout << "Nonce: " << nonce << endl << "Key eph: " << eph_pub_key << endl;
	//cout << "to sign: " << endl << to_sign << endl;
	memory_handler(SERVER, sock, sign_len, &sign_buf);
	ret = digital_sign(privK_sv, to_sign, sign_len, sign_buf);	//privK_sv
	if(ret < 0){
		error_handler("Sign error");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	sign_len = ret;
	//cout << "Sign len: " << sign_len << endl << "Ret: " << ret << endl;
	serialize_int(sign_len, sign_len_byte);	// ritorno funzione di firma



	// PROVA VERIFICA FIRMA
	//	EXTRACT PUBLIC KEY FROM CERT
	/*char *abs_path2;
	EVP_PKEY *pubK_sv = NULL;
	abs_path2 = (char*)malloc(MAX_PATH);
	getcwd(abs_path2, MAX_PATH);
	X509 *cert2 = NULL;
	FILE *cert_file = NULL;

	string pem_path2 = strcat(abs_path2, "/server_src/cert/servercert.pem");
	cout << "pem path: " << pem_path2 << endl;
	cert_file = fopen(pem_path2.c_str(), "r");
	if(!cert_file)
		cout << "not cert file" << endl;
	cert2 = PEM_read_X509(cert_file, NULL, NULL, NULL);
	if(!cert2){
		cout << "pem read fail" << endl;
		return NULL;
	}
	fclose(cert_file);
	pubK_sv = X509_get_pubkey(cert2);
	if(!pubK_sv){
		error_handler("PubKey extraction failed");
		free_var(CLIENT);
		close(sock);
		exit(0);
	}
	//unsigned char *buf = (unsigned char*)malloc(MAX_PATH), prova[3] = {'a', 'b', 'c'};
	//int len2 = 0;
	//len2 = digital_sign(privK_sv, prova, 3, buf);
	//ret = digital_sign_verify(pubK_sv, buf, len2, prova, 3);
	//ret = digital_sign_verify(pubK_sv, sign_buf, sign_len, to_sign, key_len + NONCE_LEN);
	//if(ret < 0)
	//	cout << "schianto" << endl << "ret: " << ret << endl;
*/
	// FINE PROVA

	//	CERTIFICATE SERIALIZATION
	getcwd(abs_path, MAX_PATH);
	string path = strcat(abs_path, "/server_src/cert/servercert.pem");
	unsigned char *cert_buf = serialize_certificate(path, &cert_len);

	if(!cert_buf)
		cout << "cert_buf NULL" << endl;
	memory_handler(SERVER, sock, sizeof(int), &cert_len_byte);
	serialize_int(cert_len, cert_len_byte);

	payload_len = sizeof(int) + sign_len + sizeof(int) + key_len + sizeof(int) + cert_len;
	cout << "pay len: " << payload_len << endl;
	serialize_int(payload_len, payload_len_byte);

	int resp_msg_len = sizeof(int) + payload_len;
	unsigned char *resp_msg;
	memory_handler(SERVER, sock, resp_msg_len, &resp_msg);

	memcpy((unsigned char*)resp_msg, payload_len_byte, sizeof(int));
	memcpy((unsigned char*)&resp_msg[sizeof(int)], sign_len_byte, sizeof(int));
	memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int)], sign_buf, sign_len);
	memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + sign_len], key_len_byte, sizeof(int));
	memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + sign_len + sizeof(int)], eph_pub_key, key_len);
	memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + sign_len + sizeof(int) + key_len], cert_len_byte, sizeof(int));
	memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + sign_len + sizeof(int) + key_len + sizeof(int)], cert_buf, cert_len);

	//	SEND MSG
	if((ret = send(sock, (void*)resp_msg, resp_msg_len, 0)) < 0){
		error_handler("send() failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}

	//	RECEIVE CLIENT CRYPTO DATA	[pay len][sign len][sign][ciph len][ciphertext][len cripted key][cripted key][tag][iv]

	payload_len = 0;
	sign_len = 0;
	key_len = 0;
	int ct_len, key_enc_len;
	unsigned char *iv, *tag;
	unsigned char *ciphertext, *sign_to_verify, *sign_check, *key_enc;
	unsigned char *ct_len_byte, *key_enc_len_byte;
	EVP_PKEY *pubK_cl;

	//	READ PAYLOAD LEN
	if((ret = read_byte(sock, (void*)payload_len_byte, sizeof(int))) < 0){
		error_handler("recv() [rcv_msg] failed 1");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 1");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	memcpy(&payload_len, payload_len_byte, sizeof(int));

	//	READ SIGN_LEN & SIGN			
	if((ret = read_byte(sock, (void*)sign_len_byte, sizeof(int))) < 0){
		error_handler("recv() [sign_len_byte] failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 2");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	memcpy(&sign_len, sign_len_byte, sizeof(int));
	memory_handler(SERVER, sock, sign_len, &sign_to_verify);
	if((ret = read_byte(sock, (void*)sign_to_verify, sign_len)) < 0){
		error_handler("recv() [sign_buf] failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 32");
		free_var(SERVER);
		close(sock);
		exit(0);
	}

	//	READ CIPHERTEXT LEN & CIPHERTEXT
	memory_handler(SERVER, sock, sizeof(int), &ct_len_byte);
	if((ret = read_byte(sock, (void*)ct_len_byte, sizeof(int))) < 0){
		error_handler("recv() [ct_len_byte] failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 33");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	memcpy(&ct_len, ct_len_byte, sizeof(int));
	memory_handler(SERVER, sock, ct_len, &ciphertext);
	if((ret = read_byte(sock, (void*)ciphertext, ct_len)) < 0){
		error_handler("recv() [ciphertext] failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 34");
		free_var(SERVER);
		close(sock);
		exit(0);
	}

	//	READ ENC KEY
	memory_handler(SERVER, sock, sizeof(int), &key_enc_len_byte);
	if((ret = read_byte(sock, (void*)key_enc_len_byte, sizeof(int))) < 0){
		error_handler("recv() [key_enc_len_byte] failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 35");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	memcpy(&key_enc_len, key_enc_len_byte, sizeof(int));
	memory_handler(SERVER, sock, key_enc_len, &key_enc);
	if((ret = read_byte(sock, (void*)key_enc, key_enc_len)) < 0){
		error_handler("recv() [key_enc] failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 36");
		free_var(SERVER);
		close(sock);
		exit(0);
	}

	//	READ TAG & IV
	memory_handler(SERVER, sock, TAG_LEN, &tag);
	memory_handler(SERVER, sock, IV_LEN, &iv);
	if((ret = read_byte(sock, (void*)tag, TAG_LEN)) < 0){
		error_handler("recv() [tag] failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 37");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if((ret = read_byte(sock, (void*)iv, IV_LEN)) < 0){
		error_handler("recv() [iv] failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	if(ret == 0){
		error_handler("nothing to read! 38");
		free_var(SERVER);
		close(sock);
		exit(0);
	}

	//	READ CLIENT PUBLIC KEY
	string key_path2 = "/server_src/pub_key/" + username + "_public_key.pem";
	FILE *pem_fd2 = fopen(key_path2.c_str(), "r");
	if(!pem_fd2){
		error_handler("Can't open PEM file 222");
		free_var(SERVER);
		close(sock);
		exit(0);
	}
	pubK_cl = PEM_read_PrivateKey(pem_fd2, NULL, NULL, NULL);

	//	SIGNATURE VERIFICATION
	memory_handler(SERVER, sock, ct_len + key_len, &sign_check);
	memcpy((unsigned char*)sign_check, ciphertext, ct_len);
	memcpy((unsigned char*)&sign_check[ct_len], eph_pub_key, key_len);

	ret = digital_sign_verify(pubK_cl, sign_check, ct_len + key_len, sign_to_verify, sign_len);
	if(ret != 1){
		error_handler("Sign not valid 2");
		free_var(SERVER);
		close(sock);
		exit(0);
	}

	//	DECRYPT SESSION KEY
	memory_handler(SERVER, sock, ct_len, &session_key);
	ret = envelope_decrypt(eph_key_priv, ciphertext, ct_len, key_enc, key_enc_len, iv, session_key);
	if(ret < 0){
		error_handler("Decrypt session key failed");
		free_var(SERVER);
		close(sock);
		exit(0);
	}

	return 1;
}

void print_Server_cert_info(X509* server_cert){

    char* tmp = X509_NAME_oneline(X509_get_subject_name(server_cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(server_cert), NULL, 0);
    //cout << "\nCertificate of \n\t" << tmp << "\n\t(released by " << tmp2 << ") \n\tEND INFO\n\n";

    //PEM_write_X509(stdout, server_cert);
    free(tmp);
    free(tmp2);

}
//	END UTILITY FUNCTIONS





