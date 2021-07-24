#ifndef __SHA256_H
#define __SHA256_H


int mysha256(const char *readstr, unsigned char *md);
int APKsha256(const unsigned char *readstr, unsigned char *md, size_t len);
void printf256(unsigned char *md);
#endif
