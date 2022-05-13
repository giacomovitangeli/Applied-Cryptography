#include <iostream>
#include <cstdlib>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;
int main() {
 	RAND_poll();
 	unsigned char key[16];
 	unsigned char iv[16];
	 RAND_bytes(key, 16);
	 RAND_bytes(iv, 16);
 	/* proceeds with encryption */
	cout<<key[4]<<endl;
return 0;
}
