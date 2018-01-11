#include <iostream>
#include <cstring>
#include <cassert>

#include <openssl/bio.h>
#include <openssl/err.h>

using namespace std;

int main(int argc, char** argv){
	(void) argc;
	(void) argv;

	BIO* testBio;
	testBio = BIO_new(BIO_s_mem());

	char block1[50];
	memset(block1, 0x1, 50);

	char block2[30];
	memset(block2, 0x2, 30);

	char block3[90];
	memset(block3, 0x3, 90);

	char buf[100];
	memset(buf, 0, 100);

	assert(BIO_read(testBio, buf, 100) == -1);
	assert(BIO_read(testBio, buf, 100) == -1);

	BIO_write(testBio, block1, 50);
	BIO_write(testBio, block2, 30);

	assert(BIO_read(testBio, buf, 100) == 80);
	for(int i=0; i<50; i++){
		assert(buf[i] == 1);
	}
	for(int i=50; i<80; i++){
		assert(buf[i] == 2);
	}

	assert(BIO_read(testBio, buf, 100) == -1);

	BIO_write(testBio, block1, 50);

	assert(BIO_read(testBio, buf, 100) == 50);
	for(int i=0; i<50; i++){
		assert(buf[i] == 1);
	}

	BIO_write(testBio, block2, 30);
	BIO_write(testBio, block3, 90);

	assert(BIO_read(testBio, buf, 100) == 100);
	for(int i=0; i<30; i++){
		assert(buf[i] == 2);
	}
	for(int i=30; i<100; i++){
		assert(buf[i] == 3);
	}
	assert(BIO_read(testBio, buf, 100) == 20);
	for(int i=0; i<20; i++){
		assert(buf[i] == 3);
	}

	assert(BIO_read(testBio, buf, 100) == -1);
}
