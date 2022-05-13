all: client server


client: main_client.o
	g++ -Wall main_client.o -o client -lcrypto



main_client.o: main_client.cpp
	g++ -Wall -c -g main_client.cpp -lcrypto



server: main_server.o
	g++ -Wall main_server.o -o server -lcrypto



main_server.o: main_server.cpp
	g++ -Wall -c -g main_server.cpp -lcrypto



clean:
	rm *o client server

