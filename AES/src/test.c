#include "../header/aes.h"
#include "../header/aes_modes.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void print(unsigned char* text, size_t size) {
    for (int i = 0; i < size; ++i)
        printf("%d ", text[i]);
    printf("\n");
}

int main() {

    Block128 user_key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    Block128 keys[11];
    gen_key_schedule_128(user_key, keys);

    size_t plaintextsize = 100000000;
    unsigned char* plaintext = (unsigned char*)malloc(plaintextsize);
    unsigned char* ciphertext = (unsigned char*)malloc(plaintextsize + 100);
    unsigned char* deciphertext = (unsigned char*)malloc(plaintextsize + 10);

    for (int i = 0; i < plaintextsize; ++i)  plaintext[i] = rand() % 256;

    clock_t start, end;
    double cpu_time_used;

    // Start the clock
    start = clock();


    size_t ciphertextsize = AES_OFB_encrypt(ciphertext, plaintext, plaintextsize, keys);

    size_t deciphertextsize = AES_OFB_decrypt(deciphertext, ciphertext, ciphertextsize, keys);

    end = clock();

    printf("%d %d %d %d", memcmp(plaintext, deciphertext, plaintextsize), plaintextsize, ciphertextsize, deciphertextsize);


    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    printf("\nExecution time: %f milliseconds\n", cpu_time_used);


    return 0;

}


