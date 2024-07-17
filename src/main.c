#define OPENSSL_API_COMPAT 0x10100000L
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define NAME_MAX 256
#define BUFF_SIZE 2048

int main(void) {
    const char file_name[NAME_MAX] = "test/1.txt";
    FILE *fp;
    fp = fopen(file_name, "rb");
    if(fp == NULL) {
        printf("n/a\n");
        exit(1);
    }
    SHA256_CTX c;
    SHA256_Init(&c);
    char data[2048] = "";
    size_t len;
    while((len = fread(data, 1, sizeof(data), fp)) > 0) {
        SHA256_Update(&c, data, len);
    }
    unsigned char sum[32];
    SHA256_Final(sum, &c);
    fclose(fp);
    char buffer[BUFF_SIZE];
    for(int i = 0; i < 32; ++i) {
        sprintf(buffer + i * 2, "%02x", sum[i]);
    }

    const char test_file[NAME_MAX] = "test.txt"; 
    FILE *tfp;
    tfp = fopen(test_file, "w+");
    if(tfp == NULL) {
        printf("n/a\n");
        exit(1);
    }
    fprintf(tfp, "%s  %s\n", buffer, file_name);
    fclose(tfp);
    return 0;
}
