#define OPENSSL_API_COMPAT 0x10100000L
#include <ctype.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>

void file_processing(const char file_name[256], const char *log_file);
void sha256sum(const char file_name[256], char buffer[65]);
void write_log(const char buffer[65], const char log_file[256], const char file_name[256]);
void usage_message();
void set(char *dir_name, const char *log_file);
int check(char dir_name[256], const char *log_file);
void info_message(char *mode, char *dir_name, char *log_file);
int check_format(char *buffer);
int get_file_list(char *dir_name, char **file_list);
void free_file_list(char **file_list, int size);

int main(int argc, char **argv) {
    if (argc == 4) {
        if (strcmp(argv[1], "set") == 0) {
            set(argv[2], argv[3]);
            info_message(argv[1], argv[2], argv[3]);
        } else if (strcmp(argv[1], "check") == 0) {
            if (check(argv[2], argv[3])) info_message(argv[1], argv[2], argv[3]);
        } else
            usage_message();
    } else
        usage_message();
    return 0;
}

int check_format(char *buffer) {
    int format_flag = 1;
    buffer[strcspn(buffer, "\n")] = '\0';
    if (strlen(buffer) < 67) format_flag = 0;
    for (int i = 0; i < 64 && format_flag; ++i) {
        if (isxdigit(buffer[i]) == 0) format_flag = 0;
    }
    if (!(buffer[64] == ' ' && buffer[65] == ' ')) format_flag = 0;
    return format_flag;
}

void info_message(char *mode, char *dir_name, char *log_file) {
    syslog(LOG_INFO, "mode:%s dir:%s integrity certified from %s log file", mode, dir_name, log_file);
    printf("mode:%s dir:%s integrity certified, from %s log file\n", mode, dir_name, log_file);
}

void file_processing(const char file_name[256], const char *log_file) {
    char buffer[65];
    sha256sum(file_name, buffer);
    write_log(buffer, log_file, file_name);
}

void sha256sum(const char file_name[256], char buffer[65]) {
    FILE *fp;
    fp = fopen(file_name, "rb");
    if (fp == NULL) {
        syslog(LOG_ERR, "file:%s was deleted\n", file_name);
        printf("file:%s was deleted\n", file_name);
    } else {
        SHA256_CTX c;
        SHA256_Init(&c);
        char data[2048] = "";
        size_t len;
        while ((len = fread(data, 1, sizeof(data), fp)) > 0) {
            SHA256_Update(&c, data, len);
        }
        unsigned char sum[SHA256_DIGEST_LENGTH];
        SHA256_Final(sum, &c);

        for (int i = 0; i < 32; ++i) {
            sprintf(buffer + i * 2, "%02x", sum[i]);
        }
        buffer[64] = '\0';
        fclose(fp);
    }
}

void write_log(const char buffer[65], const char log_file[256], const char file_name[256]) {
    FILE *tfp;
    tfp = fopen(log_file, "a+");
    if (tfp == NULL) {
        syslog(LOG_ERR, "can't open %s log file", log_file);
        printf("can't open %s log file\n", log_file);
        exit(1);
    }
    fprintf(tfp, "%s  %s\n", buffer, file_name);
    fclose(tfp);
}

void usage_message() {
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
    if (dp == NULL) {
        syslog(LOG_ERR, "can't open dir:%s", dir_name);
        printf("can't open dir:%s\n", dir_name);
        exit(2);
    }
    const struct dirent *entry;

    FILE *tfp;
    tfp = fopen(log_file, "w");
    if (tfp == NULL) {
        syslog(LOG_ERR, "can't open %s log file", log_file);
        printf("can't open %s log file\n", log_file);
        exit(1);
    }
    fclose(tfp);

    while ((entry = readdir(dp)) != NULL) {
        char file_name[512];
        sprintf(file_name, "%s/%s", dir_name, entry->d_name);

        struct stat path_stat;
        stat(file_name, &path_stat);
        if (S_ISREG(path_stat.st_mode)) file_processing(file_name, log_file);
    }
    closedir(dp);
}

int check(char dir_name[256], const char *log_file) {
    FILE *fp = fopen(log_file, "r");
    if (fp == NULL) {
        syslog(LOG_ERR, "can't open %s log file", log_file);
        printf("can't open %s log file\n", log_file);
        exit(3);
    }
    char buffer[512];
    int err_flag = 1;
    char **file_list = (char **)malloc(sizeof(char *) * 100);
    int size = get_file_list(dir_name, file_list);

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (check_format(buffer) == 0) {
            syslog(LOG_ERR, "incorrect format %s", log_file);
            printf("incorrect format %s\n", log_file);
            fclose(fp);
            exit(4);
        }
    }
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        char sum_from_log[65];
        char file_name[256];
        sscanf(buffer, "%64s  %255s", sum_from_log, file_name);

        int in_list = 1;
        for (int i = 0; i < size && in_list; ++i) {
            if (strcmp(file_list[i], file_name) == 0) {
                in_list = 0;
            }
        }
        if (in_list == 0) {
            syslog(LOG_ERR, "file:%s/%s is added", dir_name, log_file);
            printf("file:%s/%s is added\n", dir_name, log_file);
            err_flag = 0;
        } else {
            char sum_from_file[65];
            sha256sum(file_name, sum_from_file);
            if (strcmp(sum_from_log, sum_from_file) != 0) {
                syslog(LOG_ERR, "file:%s/%s has been modified", dir_name, log_file);
                printf("file:%s/%s has been modified\n", dir_name, log_file);
                err_flag = 0;
            }
        }
    }
    free_file_list(file_list, size);
    fclose(fp);
    return err_flag;
}

int get_file_list(char *dir_name, char **file_list) {
    size_t len = strlen(dir_name);
    if (dir_name[len - 1] == '/') {
        dir_name[len - 1] = '\0';
    }

    DIR *dp = opendir(dir_name);
    if (dp == NULL) {
        syslog(LOG_ERR, "can't open dir:%s", dir_name);
        printf("can't open dir:%s\n", dir_name);
        exit(2);
    }

    const struct dirent *entry;
    int index = 0;
    while ((entry = readdir(dp)) != NULL) {
        char file_name[512];
        sprintf(file_name, "%s/%s", dir_name, entry->d_name);

        struct stat path_stat;
        stat(file_name, &path_stat);
        if (S_ISREG(path_stat.st_mode)) {
            file_list[index] = (char *)malloc(strlen(entry->d_name) + 1);
            strcpy(file_list[index], entry->d_name);
            ++index;
        }
    }
    closedir(dp);
    return index;
}

void free_file_list(char **file_list, int size) {
    for (int i = 0; i < size; ++i) {
        free(file_list[i]);
    }
    free(file_list);
}
