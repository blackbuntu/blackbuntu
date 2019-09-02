#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

void PBKDF2_HMAC_SHA512(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult) 
{ 
	unsigned int i; 
	unsigned char digest[outputBytes]; 
	PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen((const char*)salt), iterations, EVP_sha512(), outputBytes, digest); 
	for (i = 0; i < sizeof(digest); i++) 
		sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]); 
}

void PBKDF2_HMAC_SHA1(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult) 
{ 
	unsigned int i; 
	unsigned char digest[outputBytes]; 
	PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen((const char*)salt), iterations, EVP_sha1(), outputBytes, digest); 
	for (i = 0; i < sizeof(digest); i++) 
		sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]); 
}

void PBKDF2_HMAC_MD5(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult) 
{ 
	unsigned int i; 
	unsigned char digest[outputBytes]; 
	PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen((const char*)salt), iterations, EVP_md5(), outputBytes, digest); 
	for (i = 0; i < sizeof(digest); i++) 
		sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]); 
}

void usage()
{
	fprintf(stderr, "Usage: pbkdf2 pwd salt iter olen\n");
	exit(1);
}


int main(int argc, char *argv[])
{
	if (argc != 5)
		usage();
	int olen = atol(argv[4])/8;
	char* obuf = (char*)malloc(1+2*olen);
	OPENSSL_init();
	PBKDF2_HMAC_SHA1(argv[1], (unsigned char*)argv[2], atol(argv[3]), olen, obuf);
	printf("PBKDF2(SHA1  , ...) = %s\n", obuf);
	PBKDF2_HMAC_SHA512(argv[1], (unsigned char*)argv[2], atol(argv[3]), olen, obuf);
	printf("PBKDF2(SHA512, ...) = %s\n", obuf);
	PBKDF2_HMAC_MD5(argv[1], (unsigned char*)argv[2], atol(argv[3]), olen, obuf);
	printf("PBKDF2(MD5   , ...) = %s\n", obuf);
	free(obuf);
	return 0;
}
