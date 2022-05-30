/*		CLIENT -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

#include "data_struct.h"

using namespace std;

/* TEST ONLY */
unsigned char key[] = "password12345678password12345678";
unsigned char iv[] = "123456789012";
/*	END*/


int main(){

    int socket_d, len, ret;
    unsigned char *rcv_msg, *resp_msg, *cipher, tag[16], *plaintext, *ciphertext;
    uint16_t lmsg;
    struct sockaddr_in sv_addr;
    struct dummy_packet packet;

    /*	Cleanup and initialization	 */
    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_port = htons(4242); //RANDOM port number
    if((ret = inet_pton(AF_INET, "127.0.0.1", &(sv_addr.sin_addr))) == 0)
        error_handler("address format not valid");

    if((socket_d = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        error_handler("socket creation failed");

    cout << "> Socket creato correttamente!" << endl;

    if((ret = connect(socket_d, (struct sockaddr*)&sv_addr, sizeof(sv_addr))) < 0)
        error_handler("connect() failed");

    print_man();

    /* Endless loop - Managing entire session */

    while(1) {
        plaintext = (unsigned char *) malloc(1024);
        ciphertext = (unsigned char *) malloc(1024);
        cout << "Enter a message.." << endl;
        cin >> plaintext;


        int cmd = 0;


        //todo funzione per check parametri dei comandi
        check_cmd(plaintext, &cmd);
        return 0;
/*
        switch(cmd){
            case 1:
                print_man();
                break;
            case 2:

            case 3:

            case 4:

            case 5:

            case 6:

            default:
                cout<<"Command not found"<<endl<<"type 'man' for the Manual"<<endl;
                break;
        }

        if(cmd==1)//provvisorio
            continue;
*/


        ret = strlen((char*)plaintext);
        len = gcm_encrypt(plaintext, ret, iv, 12, key, iv, 12, packet.ciphertext, packet.tag);

        lmsg = htons(len);
        if((ret = send(socket_d, (void*)&lmsg, sizeof(uint16_t), 0)) < 0)
            error_handler("send() [lmsg] failed");

        if((ret = send(socket_d, (void*)packet.ciphertext, len, 0)) < 0)
            error_handler("send() [ciphertext] failed");

        if((ret = send(socket_d, (void*)packet.tag, 16, 0)) < 0)
            error_handler("send() [tag] failed");

        memset(plaintext, 0, 1024);
        memset(ciphertext, 0, 1024);
        memset(tag, 0, 16);

        if((ret = recv(socket_d, (void*)&lmsg, sizeof(uint16_t), 0)) < 0)
            error_handler("recv() [lmsg] failed");

        if((ret = recv(socket_d, (void*)ciphertext, len, 0)) < 0)
            error_handler("recv() [ciphertext] failed");

        if((ret = recv(socket_d, (void*)tag, 16, 0)) < 0)
            error_handler("recv() [tag] failed");

        gcm_decrypt(ciphertext, len, iv, 12, tag, key, iv, 12, plaintext);
        cout << plaintext << endl;


    }
    return 0; //Unreachable code
}
