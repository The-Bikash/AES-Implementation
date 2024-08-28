#ifndef __AES_MODES__
#define __AES_MODES__

#include "aes.h"
#include <stdio.h>

Block128 pkcs7_pad(unsigned char* _Src, size_t _Len) {
    unsigned char _Remainder = _Len % 16;
    unsigned char _PadVal = 16 - _Remainder;
    _Src = _Src + _Len - _Remainder;
    Block128 _Tmp; unsigned char i = 0;
    for (; i < _Remainder; ++i)
        _Tmp.cells[i] = _Src[i];
    for (; i < 16; ++i)
        _Tmp.cells[i] = _PadVal;
    return _Tmp;
}

size_t pkcs7_unpad(unsigned char* _Src, size_t _Len) {
    unsigned char _PadVal = _Src[_Len - 1];
    if (_PadVal > 0 && _PadVal <= 16)
        for (unsigned char i = 0; i < _PadVal; ++i)
            if (_Src[_Len - 1 - i] != _PadVal)
                return _Len;
    return _Len - _PadVal;
    return _Len;
}

size_t AES_ECB_encrypt(void* _Dst, void* _Src, size_t _Size, void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    Block128* _SrcPtr = (Block128*)_Src;
    Block128* _KeyPtr = (Block128*)_Key;

    size_t _NewSize = _Size / 16;
    size_t i = 0;
    for (; i < _NewSize; ++i)
        _DstPtr[i] = _aes_encrypt(_SrcPtr[i], _KeyPtr);
    _DstPtr[i] = _aes_encrypt(pkcs7_pad((unsigned char*)_Src, _Size), _KeyPtr);
    return (i + 1) * 16;
}

size_t AES_ECB_decrypt(void* _Dst, void* _Src, size_t _Size, void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    Block128* _SrcPtr = (Block128*)_Src;
    Block128* _KeyPtr = (Block128*)_Key;

    size_t _NewSize = _Size / 16;
    for (size_t i = 0; i < _NewSize; ++i)
        _DstPtr[i] = _aes_decrypt(_SrcPtr[i], _KeyPtr);
    return pkcs7_unpad((unsigned char*)_Dst, _Size);
}

#endif
