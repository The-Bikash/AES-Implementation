#include "../header/aes.h"
#include "../header/aes_modes.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {

    Block128 user_key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    Block128 keys[11];
    gen_key_schedule_128(user_key, keys);

    const size_t size = 10000;

    unsigned char* plaintext = (unsigned char*)malloc(size);
    unsigned char* ciphertext = (unsigned char*)malloc(size + 100);
    unsigned char* deciphertext = (unsigned char*)malloc(size + 10);

    size_t ciphertextsize = AES_ECB_encrypt(ciphertext, plaintext, size, keys);

    size_t deciphertextsize = AES_ECB_decrypt(deciphertext, ciphertext, ciphertextsize, keys);

    int i = memcmp(plaintext, deciphertext, size);

    printf("%d", i);


    return 0;

}


