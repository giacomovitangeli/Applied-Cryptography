#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <ctime>
#include <cerrno>
#include <malloc/malloc.h> // Piero: malloc path must be malloc/malloc.h; Altri: malloc path is malloc.h
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#define PORT 4242

using namespace std;

int main(){
	int listner_socket = 0, new_socket = 0, ret = 0, option = 1, k = 0, fdmax;
	//char *resp_msg = 0, *rcv_msg = 0;
	string *resp_msg = 0, *rcv_msg = 0;
	uint16_t lmsg; //fixme *len;
	struct sockaddr_in my_addr, client_addr;
	fd_set master; 
	fd_set read_set;


	FD_ZERO(&master);
	FD_ZERO(&read_set);

	listner_socket = socket(AF_INET, SOCK_STREAM, 0); // Creazione listner
    setsockopt(listner_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));	//permette di riusare il solito indirizzo per il socket, necessario per provare senza dover spengere la virtual machine
    if(listner_socket < 0){
        printf("Errore nella creazione del socket di comunicazione!\n");
        exit(0);
    }
    printf(">>> Socket creato correttamente!\n");
	
    //	Pulizia e inizializzazione strutture server
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(PORT); //4242 porta CASUALE
    my_addr.sin_addr.s_addr = INADDR_ANY; // vincola il socket a tutte le interfacce, usare inet_addr("127.0.0.1"); se si vuole utilizzare il solo indirizzo locale

    ret = bind(listner_socket, (struct sockaddr*)&my_addr, sizeof(my_addr));
    if(ret < 0){
        perror("Errore nella bind: \n");
        exit(0);
    }
    
    ret = listen(listner_socket, 10); // 10 = numero massimo di connessioni in attesa, l'11esima verrà rifiutata -- 10 numero CASUALE
    if(ret < 0){
        perror("Errore nella listen: \n");
        exit(0);
    }
    printf(">>> Socket associato correttamente all'indirizzo!\n");
	FD_SET(listner_socket, &master);	// Aggiungo il listner al master
	fdmax = listner_socket;
    int len = sizeof(client_addr);


	while(1){	//Processo unico, client multipli gestiti tramite select()
		read_set = master;
		select(fdmax + 1, &read_set, NULL, NULL, NULL);
		for(k = 0; k <= fdmax; k++){
			if(FD_ISSET(k, &read_set)){
				if(k == listner_socket){ // Sono il listner
					printf(">>> In attesa di connessione...\n\n");

                    new_socket = accept(listner_socket, (struct sockaddr*)&client_addr,
                                        reinterpret_cast<socklen_t *>(&len));

                    if(new_socket < 0){
            			perror("Errore nella creazione del socket di comunicazione!\n");
            			exit(0);
        			}
					FD_SET(new_socket, &master);
					if(new_socket > fdmax)
						fdmax = new_socket;
				}
				else{	// Non sono il listner
					printf(">>> In attesa di un comando dal client...\n\n");
					// Alloco spazio per i messaggi sia in entrata che in uscita
					rcv_msg = (string*)malloc(128);
					if(!rcv_msg)
						exit(0);
					resp_msg = (string*)malloc(128);
					if(!resp_msg)
						exit(0);
					// RICEVO LA LUNGHEZZA DEL MESSAGGIO
					ret = recv(k, (void*)&lmsg, sizeof(uint16_t), 0);
					if(ret == 0){
						printf("Comunicazione col client interrotta!\n");
						exit(0);
					}
					if(ret < 0){
		                printf("Errore nella recv!\n");
		                exit(0);
		            }
					// RICEVO IL MESSAGGIO
					len = ntohs(lmsg);
					ret = recv(k, (void*)rcv_msg, len, 0);
					if(ret == 0){
						printf("Comunicazione col client interrotta!\n");
						exit(0);
					}
		            if(ret < 0){
		                printf("Errore nella recv!\n");
		                exit(0);
		            }
					printf("%s", rcv_msg);
		            fgets(reinterpret_cast<char *>(resp_msg), 128, stdin);
					len = strlen(reinterpret_cast<const char *>(resp_msg));
		            lmsg = htons(len);
		            send(k, (void*)&lmsg, sizeof(uint16_t), 0);
		            send(k, (void*)resp_msg, len, 0);
					
					memset(rcv_msg, 0, 128);
					memset(resp_msg, 0, 128);
				}
			}
		}
	}
}