#include "../header/aes.h"
#include "../header/aes_modes.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void print(Block128 x) {
    printf("\n");
    for (unsigned char i = 0; i < 16; ++i) printf("%d ", x.cells[i]);
}

int main() {
    _Seed(clock() * clock());

    Block128 user_key = random_message();
    Block128 keys[11] = { user_key };

    gen_key_schedule_128(keys);

    char message[] = "Imagine failing at a major project, lying to your woman and getting caught, or overhearing her\
        joke about your shortcomings in bed.How do you react with your body, breath, and eyes ? Notice if you\
        react to a person or situation that hurts you by withdrawing, hiding, or closing in on yourself.Notice if\
        there are times when you find it difficult to look into someone's eyes, or times when your chest and solar\
        plexus become tense and contracted.These are signs of an unskillful reaction to hurt.Contracted and\
        closed in on yourself, you are unable to act.You are trapped in your own self - protective tension, no\
        longer a free man.\
        The superior man practices opening during these times of automatic closure.Open the front of\
        your body so your chest and solar plexus are not tense.Sit or stand up straight and full, opening the front\
        of your body, softening your chest and belly, wide and free.Breathe down through your chest and solar\
        plexus, deep into your belly.Look directly into the eyes of whoever you are with, feeling your own pain\
        as well as feeling the other person.Only when the front of your body is relaxed and opened, your breath\
        full and deep, and your gaze unguarded and directly connected with another person's eyes, can your\
        fullest intelligence manifest spontaneously in the situation.To act as a superior man, a samurai of\
        relationship, you must feel the entire situation with your whole body.A closed body is unable to sense\
        subtle cues and signals, and therefore unable to act with mastery in the situation";

    char cipher_text[5000];
    char decipher_text[5000];
    clock_t start = clock();

    printf("message : %s\n", message);
    printf("size of message : %llu\n\n", sizeof(message));

    size_t size = AES_ECB_encrypt(cipher_text, message, sizeof(message), keys);
    cipher_text[size] = '\0';

    printf("cipher text : ");
    fwrite(cipher_text, 1, size, stdout);
    printf("\nsize of cipher text : %llu\n\n", size);

    size_t size1 = AES_ECB_decrypt(decipher_text, cipher_text, size, keys);
    decipher_text[size1] = '\0';

    printf("decipher text : %s\n", decipher_text);
    printf("size of decipher text : %llu\n\n", size1);

    clock_t end = clock();
    double execution_time_ms = (double)(end - start) * 1000 / CLOCKS_PER_SEC;
    printf("Execution time: %f ms\n", execution_time_ms);
    printf("SUCCESS");
}


