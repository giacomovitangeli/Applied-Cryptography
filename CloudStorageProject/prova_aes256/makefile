all: client server



client: main_client.o header.o

	g++ -Wall main_client.o header.o -o client -lcrypto



main_client.o: main_client.cpp

	g++ -Wall -c -g main_client.cpp -lcrypto

header.o: header.cpp
	gcc -Wall -c -g header.cpp -lcrypt



server: main_server.o header.o

	g++ -Wall main_server.o header.o -o server -lcrypto



main_server.o: main_server.cpp

	g++ -Wall -c -g main_server.cpp -lcrypto





clean:

	rm *o client server