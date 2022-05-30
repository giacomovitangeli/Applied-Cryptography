all: client server

client: main_client.o util_fun.o 
	g++ -Wall main_client.o util_fun.o -o client -lcrypto

main_client.o: main_client.cpp
	g++ -Wall -c -g main_client.cpp -lcrypto

util_fun.o: util_fun.cpp data_struct.h
	gcc -Wall -c -g client_functions.c

server: main_server.o util_fun.o
	g++ -Wall main_server.o util_fun.o -o server -lcrypto

main_server.o: main_server.cpp
	g++ -Wall -c -g main_server.cpp -lcrypto

clean:
	rm *o client server
	clear