#pragma once
#ifndef __AES_FILE_ENCRYPTION__
#define __AES_FILE_ENCRYPTION__


#include "aes.h"
#include "aes_modes.h"
#include <stdlib.h>

void print_error(const char* message) {
    printf("\033[1;31mError: %s\033[0m", message); // Bold red text
}

size_t _file_size(FILE* file) {
    long original_pos = ftell(file);
    if (original_pos == -1) {
        print_error("Error getting file position\n");
        return 0;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        print_error("Error seeking to end of file\n");
        return 0;
    }
    long size = ftell(file);
    if (size == -1) {
        print_error("Error getting file size\n");
        return 0;
    }
    if (fseek(file, original_pos, SEEK_SET) != 0) {
        print_error("Error restoring file position\n");
        return 0;
    }
    return (size_t)size;
}

size_t AES_encryptfile(FILE* _Output, FILE* _Input, const void* _Key, AES_MODE _mode) {
    Block128* _KeyPtr = (Block128*)_Key;
    size_t _Size = _file_size(_Input);
    if (_Size == 0) {
        print_error("Source file is maybe empty or invalid.\n");
        return 0;
    }
    unsigned char* _Src = (unsigned char*)malloc(_Size);
    unsigned char* _Dst = (unsigned char*)malloc(_Size + 64);
    if (_Src == NULL) {
        print_error("Error allocating memory\n");
        return 0;
    }
    fread(_Src, 1, _Size, _Input);
    size_t ciphertextsize = AES_encrypt(_Dst, _Src, _Size, _Key, _mode);
    fwrite(_Dst, 1, ciphertextsize, _Output);
    free(_Src); free(_Dst);
}

size_t AES_decryptfile(FILE* _Output, FILE* _Input, const void* _Key, AES_MODE _mode) {
    Block128* _KeyPtr = (Block128*)_Key;
    size_t _Size = _file_size(_Input);
    if (_Size == 0) {
        print_error("Source file is maybe empty or invalid.\n");
        return 0;
    }
    unsigned char* _Src = (unsigned char*)malloc(_Size);
    unsigned char* _Dst = (unsigned char*)malloc(_Size);
    if (_Src == NULL || _Dst == NULL) {
        print_error("Error allocating memory\n");
        return 0;
    }
    fread(_Src, 1, _Size, _Input);
    size_t ciphertextsize = AES_decrypt(_Dst, _Src, _Size, _Key, _mode);
    fwrite(_Dst, 1, ciphertextsize, _Output);
    free(_Src); free(_Dst);
}

#endif