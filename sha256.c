#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "openssl/sha.h"
#include "sha256.h"

int mysha256(const char *readstr, unsigned char *md)
{
	if (SHA256((unsigned char*)readstr, strlen(readstr), md) == NULL) {
		printf("sha256 erro\n");
		return -1;
	}	
	return 0;
}

int APKsha256(const unsigned char *readstr, unsigned char *md, size_t len)
{

	if (SHA256(readstr, len, md) == NULL)
	{
		printf("[%s %d] %s", __FUNCTION__, __LINE__, md);
	}
	return 0;
}

void printf256(unsigned char *md)
{
	for (int i = 0; i < 32; i++) {
		printf("%02x", md[i]);
	}
	printf("\n");
}

int sha256encrypt(const char *filepath, unsigned char *md)
{
	FILE* fp;
	SHA256_CTX ctx;
	char buf[2048];
	memset(buf, 0, strlen(buf));
	fp = fopen(filepath,"rb");
	if (fp == NULL) {
		printf("Can't open \"%s\"", filepath);
		return -1;
	}
	SHA256_Init(&ctx);
	
	size_t len = 0;
	len = fread(buf,1,2047, fp);
	buf[(int)len] = '\0';
	SHA256_Update(&ctx, buf, strlen(buf));//加入新的文件快
	SHA256_Final(md, &ctx);
	fclose(fp);
	return 0;
}
int sha256Bigfile(const char *filepath, unsigned char *md)
{
	FILE* fp = NULL;
	SHA256_CTX ctx;
	unsigned int len = 1924;
	size_t gl = 0;
	char buf[len+1];
	memset(buf, 0, len);
	fp = fopen(filepath, "rb");
	if (fp == NULL) {
		printf("Can't open\n");
		return -1;
	}

	SHA256_Init(&ctx);
	for (;;) {
		memset(buf, 0, len+1);
		gl = fread(buf, 1, 1024,fp);
		if (gl <= 0) break;
		SHA256_Update(&ctx, buf,(unsigned long)gl);
	}
	SHA256_Final(md, &ctx);

	fclose(fp);
	printf256(md);

	return 0;
}

int main(int argc, char **argv)
{
	char hash[65] = {0};
	if (argc == 1) {
		printf("please input file name!\n");
		return 0;
	}
	sha256Bigfile(*(argv+1), hash);
	memset(hash, 0, 65);

	return 0;
}
