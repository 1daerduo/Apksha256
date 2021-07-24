#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "openssl/sha.h"
#include "sha256.h"

#define LEN (1024*1024*1)

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
/*
 *功能：对大文件进行hash256计算
 *参数：filepath:文件名
 *		md:保存生成的hash
 *		readlen:想要从文件中读取数据大小
 *
 */
int sha256encryptbig(const char *filepath, unsigned char *md, unsigned int readlen)
{
	FILE* fp;
	SHA256_CTX ctx;
	size_t len = 0;
	char *buf;
	buf = (char *)malloc(readlen);	// 根据readlen动态分配内存
	if (buf == NULL) {
		printf("%s %d \n", __FUNCTION__, __LINE__);
		return -1;
	}
	memset(buf, 0, (unsigned long)readlen); //内存初始化
	
	fp = fopen(filepath, "rb");		//打开文件
	if (fp == NULL) {
		printf("Can't open \"%s\"", filepath);
		return -1;
	}
	
	SHA256_Init(&ctx);				//初始化ctx
	len = fread(buf,1,(size_t)readlen, fp); //读取数据
	buf[(int)len] = '\0';
	SHA256_Update(&ctx, buf, (unsigned long)len);//加入新的文件块
	SHA256_Final(md, &ctx);
	
	fclose(fp); //记得释放
	free(buf);	//记得释放
	buf = NULL;
	return 0;
}
int sha256Bigfile(const char *filepath, unsigned char *md)
{
	FILE* fp = NULL;
	SHA256_CTX ctx;
	size_t gl = 0;
	char *buf = (char *)malloc(sizeof(char)*LEN);	//动态分配内存
	if (buf == NULL) {
		printf("%s %d\n", __FUNCTION__, __LINE__);
		return -1;
	}
	memset(buf, 0, (unsigned long)LEN); //初始化内存
	
	fp = fopen(filepath, "rb"); //打开文件
	if (fp == NULL) {
		printf("Can't open\n");
		return -1;
	}

	SHA256_Init(&ctx);	//初始化ctx
	//while(!feof(fp)) 不能用这样的检测方法去检测是否到达末尾，测试发现最终更新的sha256摘要与
	//用命令行处理出来的摘要不一样,可能读不到末尾
	for (;;) {
		//memset(buf, 0, (unsigned long)LEN);
		gl = fread(buf, 1, (size_t)(LEN),fp);	//反复读取，直到读完
		if (gl <= 0) break;
		SHA256_Update(&ctx, buf,(unsigned long)gl);//更新数据块
	}
	SHA256_Final(md, &ctx);	//结束更新，生成sha256 hahs到md中

	fclose(fp);
	free(buf);
	buf = NULL;	//记得释放
	printf256(md);

	return 0;
}

int main(int argc, char **argv)
{
	clock_t start, end;
	char hash[65] = {0};
	if (argc == 1) {
		printf("please input file name!\n");
		return 0;
	}
	start = clock();
	sha256Bigfile(*(argv+1), hash);
	end = clock();
	printf("t:%f\n",((double)(end - start)) / CLOCKS_PER_SEC);
	
	memset(hash, 0, 65);
	start = clock();
	sha256encryptbig(*(argv+1), hash, 60*1024*1024);
	end = clock();
	printf("t:%f\n",((double)(end - start)) / CLOCKS_PER_SEC);
	printf256(hash);
	return 0;
}
