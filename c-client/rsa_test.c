#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sodium.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    if (sodium_init() < 0)
        exit(EXIT_FAILURE);

    EVP_PKEY *pkey;

    FILE *fp = fopen("public-key.pem", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
        exit(EXIT_FAILURE);

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL)
        exit(EXIT_FAILURE);

    puts("1");

    char *encrypted_message = NULL;
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    encrypted_message = malloc(RSA_size(rsa));
    crypto_secretstream_xchacha20poly1305_keygen(key);
    int encrypted_len;

    puts("2");

    if ((encrypted_len =
             RSA_public_encrypt(strlen((const char *)key) + 1, (unsigned char *)key,
                                (unsigned char *)encrypted_message, rsa, RSA_PKCS1_OAEP_PADDING)) == -1) {
        printf("error encrypting keys");
        return 1;
    }

    puts("3");

    FILE *out = fopen("./key.txt", "w");
    fwrite(encrypted_message, sizeof(*encrypted_message), RSA_size(rsa), out);
    fclose(out);

    puts("4");

    printf("Successfully encrypted a 32-bit key to a file");

    return 0;
}
