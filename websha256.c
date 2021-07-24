#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define MAX_DATA_LEN 1024
#define SHA256_LENTH 32

int main(int argc, char **argv)
{
	SHA256_CTX sha256_ctx;
	FILE *fp = NULL;
	char *strFilePath = argv[1];
	unsigned char SHA256result[SHA256_LENTH];
	char DataBuff[MAX_DATA_LEN];
	int len;
	int t = 0;
	int i;

	fp = fopen(strFilePath, "rb");  //打开文件

	do
	{
			SHA256_Init(&sha256_ctx);

			while(!feof(fp))
			{
					memset(DataBuff, 0x00, sizeof(DataBuff));

					len = fread(DataBuff, 1, MAX_DATA_LEN, fp);
					if(len)
					{
							t += len;
							//printf("len = [%d] 1\n", len);
							SHA256_Update(&sha256_ctx, DataBuff, len);   //将当前文件块加入并更新SHA256
					}
			}

			//printf("len = [%d]\n", t);

			SHA256_Final(SHA256result,&sha256_ctx); //获取SHA256

			puts("file SHA256:");
			for(i = 0; i<SHA256_LENTH; i++) //将SHA256以16进制输出
			{
					printf("%02x", (int)SHA256result[i]);
			}
			puts("\n");

	} while(0);

	SHA256((const unsigned char*)strFilePath, strlen(strFilePath), SHA256result);   //获取字符串SHA256

	puts("string SHA256:");
	for(i = 0; i < SHA256_LENTH; i++)
	{
			printf("%02x", (int)SHA256result[i]);
	}
	puts("\n");

	return 0;
}