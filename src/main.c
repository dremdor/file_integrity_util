#define OPENSSL_API_COMPAT 0x10100000L
#include <dirent.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>

void file_processing(const char file_name[256], const char *log_file);

void write_log(const char buffer[65], const char test_file[256], const char file_name[256]);

void print_message();

void set(char *dir_name, const char *log_file);

void check();

int main(int argc, char **argv) {
    if (argc == 4) {
        if (strcmp(argv[1], "set") == 0) {
            set(argv[2], argv[3]);
            syslog(LOG_INFO, "dir:%s is under control, created %s log file", argv[2], argv[3]);
        } else if (strcmp(argv[1], "check") == 0) {
            check();
        } else
            print_message();
    } else
        print_message();
    return 0;
}

void file_processing(const char file_name[256], const char *log_file) {
    FILE *fp;
    fp = fopen(file_name, "rb");
    if (fp == NULL) {
        printf("n/a\n");
        exit(1);
    }
    SHA256_CTX c;
    SHA256_Init(&c);
    char data[2048] = "";
    size_t len;
    while ((len = fread(data, 1, sizeof(data), fp)) > 0) {
        SHA256_Update(&c, data, len);
    }
    unsigned char sum[SHA256_DIGEST_LENGTH];
    SHA256_Final(sum, &c);
    fclose(fp);

    char buffer[65];
    for (int i = 0; i < 32; ++i) {
        sprintf(buffer + i * 2, "%02x", sum[i]);
    }
    buffer[64] = '\0';

    write_log(buffer, log_file, file_name);
}

void write_log(const char buffer[65], const char test_file[256], const char file_name[256]) {
    FILE *tfp;
    tfp = fopen(test_file, "a+");
    if (tfp == NULL) {
        printf("n/a\n");
        exit(1);
    }
    fprintf(tfp, "%s  %s\n", buffer, file_name);
    fclose(tfp);
}

void print_message() {
    printf(
        "Usage: ./fiutils set [path_to_dir] [path_to_log_file]\nOr: ./fiutils check [path_to_dir] "
        "[path_to_log_file]\n");
}

void set(char *dir_name, const char *log_file) {
    size_t len = strlen(dir_name);
    if (dir_name[len - 1] == '/') {
        dir_name[len - 1] = '\0';
    }

    DIR *dp = opendir(dir_name);
    const struct dirent *entry;
    if (dp == NULL) {
        printf("n/a\n");
        exit(2);
    }
    while ((entry = readdir(dp)) != NULL) {
        char file_name[512];
        sprintf(file_name, "%s/%s", dir_name, entry->d_name);

        struct stat path_stat;
        stat(file_name, &path_stat);
        if (!S_ISDIR(path_stat.st_mode)) file_processing(file_name, log_file);
    }
    closedir(dp);
}

void check() { printf("check"); }
