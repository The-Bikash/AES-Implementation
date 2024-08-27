#include "../header/aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void print(Block128 x) {
    printf("\n");
    for (unsigned char i = 0; i < 16; ++i) printf("%d ", x.cells[i]);
}

unsigned long long _State = 123456789;
void _Seed(unsigned long long value) {
    _State += value;
}
Block128 random_message() {
    Block128 rand_msg; unsigned long long* rand_msg_ptr = (unsigned long long*) & rand_msg;
    _State ^= _State << 13;
    _State ^= _State >> 17;
    _State ^= _State << 5;
    rand_msg_ptr[0] = _State;
    _State ^= _State << 13;
    _State ^= _State >> 17;
    _State ^= _State << 5;
    rand_msg_ptr[1] = _State;
    return rand_msg;
}


int is_equal(Block128 message, Block128 decipher_text) {
    unsigned long long* message_ptr = (unsigned long long*) & message;
    unsigned long long* decipher_text_ptr = (unsigned long long*) & decipher_text;
    return (message_ptr[0] == decipher_text_ptr[0] && message_ptr[1] == decipher_text_ptr[1]);
}

int main() {
    unsigned int range = 10000000;
    _Seed(clock() * clock());
    Block128 keys[11] = { random_message() };
    gen_key_schedule_128(keys);

    clock_t start = clock();

    for (unsigned int i = 0; i < range; ++i) {
        Block128 message = random_message();
        if (!is_equal(message, _aes_decryption(_aes_encryption(message, keys), keys))) {
            print(message);
            printf("\nError Encountered");
            exit(0);
        }
    }

    clock_t end = clock();

    double execution_time_ms = (double)(end - start) * 1000 / CLOCKS_PER_SEC;
    printf("Execution time: %f ms\n", execution_time_ms);
    printf("SUCCESS");
    return 0;
}


