#ifndef __AES_MODES__
#define __AES_MODES__

#include "aes.h"
#include <stdio.h>
#include <time.h>

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

size_t AES_ECB_encrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    const Block128* _SrcPtr = (const Block128*)_Src;
    const Block128* _KeyPtr = (const Block128*)_Key;

    size_t _NewSize = _Size / 16;
    size_t i = 0;
    for (; i < _NewSize; ++i)
        _DstPtr[i] = _aes_encrypt(_SrcPtr[i], _KeyPtr);
    _DstPtr[i] = _aes_encrypt(pkcs7_pad((unsigned char*)_Src, _Size), _KeyPtr);
    return (i + 1) * 16;
}

size_t AES_ECB_decrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    const Block128* _SrcPtr = (const Block128*)_Src;
    const Block128* _KeyPtr = (const Block128*)_Key;

    size_t _NewSize = _Size / 16;
    for (size_t i = 0; i < _NewSize; ++i)
        _DstPtr[i] = _aes_decrypt(_SrcPtr[i], _KeyPtr);
    return pkcs7_unpad((unsigned char*)_Dst, _Size);
}

size_t AES_CBC_encrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    const Block128* _SrcPtr = (const Block128*)_Src;
    const Block128* _KeyPtr = (const Block128*)_Key;

    _Seed(clock());
    *_DstPtr = random_message();
    ++_DstPtr;
    size_t _NewSize = _Size / 16, i = 0;
    for (; i < _NewSize; ++i)
        _DstPtr[i] = _aes_encrypt(_XorBlock128(_SrcPtr[i], *(_DstPtr + i - 1)), _KeyPtr);
    _DstPtr[i] = _aes_encrypt(_XorBlock128(pkcs7_pad((unsigned char*)_Src, _Size), *(_DstPtr + i - 1)), _KeyPtr);
    return (i + 2) * 16;
}

size_t AES_CBC_decrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    const Block128* _SrcPtr = (const Block128*)_Src;
    const Block128* _KeyPtr = (const Block128*)_Key;

    ++_SrcPtr;
    size_t _NewSize = (_Size - 1) / 16;

    for (size_t i = 0; i < _NewSize; ++i)
        _DstPtr[i] = _XorBlock128(_aes_decrypt(_SrcPtr[i], _KeyPtr), *(_SrcPtr + i - 1));
    return pkcs7_unpad((unsigned char*)_Dst, _Size - 1);
}

#endif