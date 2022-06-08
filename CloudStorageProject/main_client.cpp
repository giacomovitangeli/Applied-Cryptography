/*		CLIENT -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

#include "data_struct.h"

using namespace std;

/* TEST ONLY */
unsigned char key[] = "password12345678password12345678";
//unsigned char iv[] = "123456789012";
/*	END*/


int main(){

    int socket_d, ret, cmd;
    unsigned char *plaintext, *command_copy;
    //uint16_t lmsg;
    struct sockaddr_in sv_addr;
    

    /*	Cleanup and initialization	 */
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

    print_man();

    // Endless loop - Managing entire session 

    while(1) {
        plaintext = (unsigned char*)malloc(1024);
	command_copy = (unsigned char*)malloc(1024);	// copy to 'cut' with strtok() inside functions
	//	check on malloc() success
        cout << "Enter a message.." << endl;
        cin.getline((char*)plaintext, 1024);

	strncpy((char*)command_copy, (char*)plaintext, strlen((char*)plaintext));
        
	
        if((cmd = check_cmd((char*)command_copy)) < 0)
			error_handler("Command not found. Type 'man' for the Manual");
			

        switch(cmd){
            case MAN:{	// man command
                	print_man();
                	break;
		}
            case LIST:{	// ls command		[payload_len][aad_len]{[opcode][nonce]}[cyph_len][dummy_byte][tag][iv]
			int payload_len, ct_len, aad_len, rc, msg_len;
    			unsigned char /**rcv_msg,*/ *resp_msg, *tag, *iv, *ciphertext, *opcode, *nonce, *aad, *aad_len_byte, *payload_len_byte, *ct_len_byte;			
		
			//	MALLOC & RAND VARIABLES
			nonce = (unsigned char*)malloc(NONCE_LEN);
			if(!nonce)
				error_handler("malloc() [nonce] failed");
			rc = RAND_bytes(nonce, NONCE_LEN);
			if(rc != 1)
				error_handler("nonce generation failed");

			iv = (unsigned char*)malloc(IV_LEN);
			if(!iv)
				error_handler("malloc() [iv] failed");
			rc = RAND_bytes(iv, IV_LEN);
			if(rc != 1)
				error_handler("iv generation failed");

			tag = (unsigned char*)malloc(TAG_LEN);
			if(!tag)
				error_handler("malloc() [tag] failed");
			
			opcode = (unsigned char*)malloc(1);
			if(!opcode)
				error_handler("malloc() [opcode] failed");
			opcode[0] = '2';

			ciphertext = (unsigned char*)malloc(1024);
			if(!ciphertext)
				error_handler("malloc() [ciphertext] failed");
			memset(ciphertext, 0, 1024);

			//	SERIALIZATION

			//	AAD SERIALIZATION
			aad_len = 1 + NONCE_LEN;	//opcode + lunghezza nonce -- opcode = unsigned char
			aad = (unsigned char*)malloc(aad_len);
			if(!aad)
				error_handler("malloc() [aad] failed");
			aad_len_byte = (unsigned char*)malloc(aad_len);	//now unused, later will see
			if(!aad_len_byte)
				error_handler("malloc() [aad_len_byte] failed");
			serialize_int(aad_len, aad_len_byte);
			memcpy(aad, opcode, sizeof(unsigned char));
			memcpy(&aad[1], nonce, NONCE_LEN);

			//	CIPHERTEXT LEN SERIALIZATION
			plaintext[0] = DUMMY_BYTE;
			ct_len = gcm_encrypt(plaintext, sizeof(char), aad, aad_len, key, iv, IV_LEN, ciphertext, tag);
			if(ct_len <= 0) 
				error_handler("encrypt() failed");
			ct_len_byte = (unsigned char*)malloc(ct_len);
			if(!ct_len_byte)
				error_handler("malloc() [ct_len_byte] failed");
			serialize_int(ct_len, ct_len_byte);

			//	PAYLOAD LEN SERIALIZATION
			payload_len = sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
			payload_len_byte = (unsigned char*)malloc(sizeof(int));
			if(!payload_len_byte)
				error_handler("malloc() [payload_len_byte] failed");
			serialize_int(payload_len, payload_len_byte);

			//	BUILD MESSAGE (resp_msg)
			msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + IV_LEN;
			resp_msg = (unsigned char*)malloc(msg_len);
			if(!resp_msg)
				error_handler("malloc() [resp_msg] failed");

			memcpy(resp_msg, payload_len_byte, sizeof(int));
			memcpy((unsigned char*)&resp_msg[sizeof(int)], aad_len_byte, sizeof(int));
			memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int)], aad, aad_len);
			memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
			memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int)], ciphertext, ct_len);
			memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len], tag, TAG_LEN);
			memcpy((unsigned char*)&resp_msg[sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], iv, IV_LEN);
			
			//	SEND PACKET
			if((ret = send(socket_d, (void*)resp_msg, msg_len, 0)) < 0)
            			error_handler("send() failed");

			cout << "send() worked! " << msg_len << endl;
			break;
		}
            case UPLOAD:{	// up command
		
			break;
		}
            case DOWNLOAD:{	// dl command

			break;
		}
            case RENAME:{	// mv command

			break;
		}
            case DELETE:{	// rm command

			break;
		}
            default:	// technically not possible
                	break;
        }
	return 0;
	//memset(plaintext, 0, 1024);
        //memset(ciphertext, 0, 1024);
        //memset(tag, 0, TAG_LEN);

    }
    return 0; //Unreachable code
}
