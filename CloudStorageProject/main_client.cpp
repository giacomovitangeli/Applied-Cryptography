#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

int main(){
	int socket1 = 0, len = 0, ret = 0, i = 0;
	char *rcv_msg = 0, *resp_msg = 0;
    uint16_t lmsg;
    struct sockaddr_in sv_addr;

	/*	Pulizia e inizializzazione strutture client	 */
	memset(&sv_addr, 0, sizeof(sv_addr)); 
	sv_addr.sin_family = AF_INET;
    sv_addr.sin_port = 4242;//htons(atoi(4242));
    if((ret = inet_pton(AF_INET, "127.0.0.1", &(sv_addr.sin_addr))) == 0){
		printf("Formato indirizzo non valido!\n");
		exit(0);
	}
    socket1 = socket(AF_INET, SOCK_STREAM, 0);
    if(socket1 < 0){
        printf("Errore nellacreazione del socket di connessione!\n");
        exit(0);
    }
    printf(">>> Socket creato correttamente!\n"); 
    ret = connect(socket1, (struct sockaddr*)&sv_addr, sizeof(sv_addr));
    if(ret < 0){
        printf("Errore di connessione!\n");
        exit(0);
    }
	
	while(1){
		resp_msg = (char*)malloc(128);
		if(!resp_msg){
			printf("Malloc failed!\n");
			exit(0);
		}
        rcv_msg = (char*)malloc(128);
		if(!rcv_msg){
			printf("Malloc failed!\n");
			exit(0);
		}
		if(i == 0){
			printf("In attesa di un comando...\n");
			fgets(resp_msg, 128, stdin);
			fflush(stdin);
		
			len = strlen(resp_msg);
			lmsg = htons(len);
			ret = send(socket1, (void*)&lmsg, sizeof(uint16_t), 0);
			if(ret < 0){
				printf("Errore nella send di lmsg!\n");
				exit(0);
			}
			ret = send(socket1, (void*)resp_msg, len, 0);
			if(ret < 0){
				printf("Errore nella send del buffer!\n");
				exit(0);
			}
			i = 1;
		}
		ret = recv(socket1, (void*)&lmsg, sizeof(uint16_t), 0);
		if(ret == 0){
			printf(">>> Connessione col server persa!\n");
			close(socket1);
			exit(0);
		}
		if(ret < 0){
			printf("Errore nella ricezione della risposta (dim) dal server (1)!\n");
			exit(0);
		}
		len = ntohs(lmsg);
		rcv_msg = (char*)malloc(len);
		if(!rcv_msg){
			printf("Malloc failed!\n");
			exit(0);
		}
		ret = recv(socket1, (void*)rcv_msg, len, 0);
		if(ret < 0){
			printf("Errore nella ricezione della risposta (buf) dal server(1)!\n");
			exit(0);
		}
		i = 0;
	}
	return 0; // inutile
}