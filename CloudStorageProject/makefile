all: client server


client: main_client.o
	g++ -Wall -lcrypto main_client.o -o client



main_client.o: main_client.cpp /usr/include/openssl/
	g++ -Wall -lcrypto -c -g main_client.cpp



server: main_server.o
	g++ -Wall -lcrypto main_server.o -o server



main_server.o: main_server.cpp /usr/include/openssl/
	g++ -Wall -lcrypto -c -g main_server.cpp



clean:
	rm *o client server

