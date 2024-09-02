#define _CRT_SECURE_NO_WARNINGS

#include "../header/aes.h"
#include "../header/aes_modes.h"
#include "../header/aes_file.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>


void to_upper_case(char* str) {
    while (*str) {
        *str = toupper((unsigned char)*str);
        str++;
    }
}
void to_lower_case(char* str) {
    while (*str) {
        *str = tolower((unsigned char)*str);
        str++;
    }
}

void print_banner(const char* message) {
    printf("\n\033[1;32m%s\033[0m\n", message); // Bold green text
    size_t len = strlen(message);
    for (size_t i = 0; i < len; ++i)
        fputc('=', stdout); // Corrected from stdin to stdout
    printf("\n\n");
}
void print_message(const char* message) {
    printf("\033[1;34m%s\033[0m", message);
}

void aes_file() {
    Block128 user_key, keys[11];
    char encryption_mode_str[4];
    char operation[10];
    AES_MODE encryption_mode;

    size_t size; int ch;

    print_banner("AES-128 File Encryption and Decryption");

    printf("\033[1;34mEnter 'encrypt' or 'decrypt' to choose operation: \033[0m");
    scanf("%9s", operation);
    while ((ch = getchar()) != '\n' && ch != EOF) {/*Discard remaining input*/ }
    to_lower_case(operation);

    while (strcmp(operation, "encrypt") != 0 && strcmp(operation, "decrypt") != 0) {
        print_error("Invalid operation. Please enter 'encrypt' or 'decrypt': ");
        scanf("%9s", operation);
        while ((ch = getchar()) != '\n' && ch != EOF) {/*Discard remaining input*/ }
        to_lower_case(operation);
    }



    printf("\033[1;34mEnter the encryption mode (ECB, CBC, OFB, CFB, CTR): \033[0m");
    scanf("%3s", encryption_mode_str);
    while ((ch = getchar()) != '\n' && ch != EOF) {/*Discard remaining input*/ }
    to_upper_case(encryption_mode_str);

    while (strcmp(encryption_mode_str, "ECB") != 0 && strcmp(encryption_mode_str, "CBC") != 0 && strcmp(encryption_mode_str, "OFB") != 0 && strcmp(encryption_mode_str, "CFB") != 0 && strcmp(encryption_mode_str, "CTR") != 0) {
        print_error("Invalid mode. Please enter one of the following: ECB, CBC, OFB, CFB, CTR: ");
        scanf("%3s", encryption_mode_str);
        while ((ch = getchar()) != '\n' && ch != EOF) {/*Discard remaining input*/ }
        to_upper_case(encryption_mode_str);
    }



    unsigned int byte;
    char input[33];
    printf("\033[1;34mEnter your 16-byte key in hex (e.g., 00112233445566778899aabbccddeeff): \033[0m");
    scanf("%32s", input);
    for (int i = 0; i < 16; ++i) {
        sscanf(&input[i * 2], "%2x", &byte);
        user_key.cells[i] = (unsigned char)byte;
    }
    while ((ch = getchar()) != '\n' && ch != EOF) {/*Discard remaining input*/ }


    if (strcmp(encryption_mode_str, "ECB") == 0)
        encryption_mode = ECB;
    else if (strcmp(encryption_mode_str, "CBC") == 0)
        encryption_mode = CBC;
    else if (strcmp(encryption_mode_str, "OFB") == 0)
        encryption_mode = OFB;
    else if (strcmp(encryption_mode_str, "CFB") == 0)
        encryption_mode = CFB;
    else if (strcmp(encryption_mode_str, "CTR") == 0)
        encryption_mode = CTR;

    gen_key_schedule_128(user_key, keys);


    clock_t start, end;
    double cpu_time_used;
    char inputpath[256]; inputpath[255] = '\0';
    char outputpath[256]; outputpath[255] = '\0';

    print_message("Enter the input file path: ");
    fgets(inputpath, sizeof(inputpath), stdin);
    size_t len = strlen(inputpath);
    if (len > 0 && inputpath[len - 1] == '\n')
        inputpath[len - 1] = '\0';
    FILE* inputfile = fopen(inputpath, "rb");

    while (inputfile == NULL) {
        print_error("Error opening input file\n");
        print_message("Enter the input file path: ");
        fgets(inputpath, sizeof(inputpath), stdin);
        len = strlen(inputpath);
        if (len > 0 && inputpath[len - 1] == '\n')
            inputpath[len - 1] = '\0';
        inputfile = fopen(inputpath, "rb");
    }

    print_message("Enter the output file path: ");
    fgets(outputpath, sizeof(outputpath), stdin);
    len = strlen(outputpath);
    if (len > 0 && outputpath[len - 1] == '\n')
        outputpath[len - 1] = '\0';
    FILE* outputfile = fopen(outputpath, "wb");

    while (outputfile == NULL) {
        print_error("Error opening output file\n");
        print_message("Enter the output file path: ");
        fgets(outputpath, sizeof(outputpath), stdin);
        len = strlen(outputpath);
        if (len > 0 && outputpath[len - 1] == '\n')
            outputpath[len - 1] = '\0';
        outputfile = fopen(outputpath, "wb");
    }

    if (strcmp(operation, "encrypt") == 0) {
        print_banner("Starting Encryption...");
        start = clock();
        size_t outputfilesize = AES_encryptfile(outputfile, inputfile, keys, encryption_mode);
        end = clock();
        if (outputfilesize == 0)
            print_error("Encryption Failed\n");
        else {
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
            printf("\033[1;32mEncryption completed in: %.2f milliseconds\033[0m\n\n", cpu_time_used);
        }
    }
    else if (strcmp(operation, "decrypt") == 0) {
        print_banner("Starting Decryption...");
        start = clock();
        size_t outputfilesize = AES_decryptfile(outputfile, inputfile, keys, encryption_mode);
        end = clock();
        if (outputfilesize == 0)
            print_error("Decryption Failed\n");
        else {
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
            printf("\033[1;32mDecryption completed in: %.2f milliseconds\033[0m\n\n", cpu_time_used);
        }
    }
    fclose(inputfile);
    fclose(outputfile);
}


int main() {
    aes_file();
    while (true) {
        print_message("Continue? : ");
        char input[33]; int ch;
        scanf("%3s", input);
        while ((ch = getchar()) != '\n' && ch != EOF) {/*Discard remaining input*/ }
        to_lower_case(input);
        if (strcmp(input, "yes") == 0)
            aes_file();
        else break;
    }

    getchar();
    return 0;
}


