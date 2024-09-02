#pragma once
#ifndef __AES_MODES__
#define __AES_MODES__

#include "aes.h"
#include <stdio.h>
#include <time.h>

/*
PKCS7 PAD :

Original Data :
+----+----+----+----+----+----+----+----+
| H  | E  | L  | L  | O  |    |    |    |
+----+----+----+----+----+----+----+----+

Padding Calculation:
Block size: 8 bytes
Length of plaintext: 5 bytes
Padding needed: 8 - 5 = 3 bytes
Padding value: 0x03

Padded Data:

+----+----+----+----+----+----+----+----+
| H  | E  | L  | L  | O  | 03 | 03 | 03 |
+----+----+----+----+----+----+----+----+

*/

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


/*

Padded Data :
+----+----+----+----+----+----+----+----+
| H  | E  | L  | L  | O  | 03 | 03 | 03 |
+----+----+----+----+----+----+----+----+

Unpadding Process :

Identify Padding Value:
Look at the last byte(s) of the padded data to determine the padding value.
In this case, the last byte is 0x03, so the padding value is 3.

Remove Padding:
Remove 3 bytes from the end of the data.

+----+----+----+----+----+
| H  | E  | L  | L  | O  |
+----+----+----+----+----+

*/

size_t pkcs7_unpad(unsigned char* _Src, size_t _Len) {
    unsigned char _PadVal = _Src[_Len - 1];
    if (_PadVal > 0 && _PadVal < 16) {
        for (unsigned char i = 0; i < _PadVal; ++i)
            if (_Src[_Len - 1 - i] != _PadVal)
                return _Len;
        return _Len - _PadVal;
    }
    return _Len;
}

void array_xor(size_t* _Dst, size_t* _Src, size_t _Len) {
    for (size_t i = 0; i < _Len; ++i)
        _Dst[i] ^= _Src[i];
}

/*

ECB(Electronic codebook mode)

Encryption:

Plaintext Block 1           Plaintext Block 2           Plaintext Block 3   ...
        |                          |                          |
        v                          v                          v
+----------------+        +----------------+        +----------------+
|  AES Encrypt   |        |  AES Encrypt   |        |  AES Encrypt   |      ...
|    (Key K)     |        |    (Key K)     |        |    (Key K)     |
+-------+--------+        +-------+--------+        +-------+--------+
        |                          |                          |
        v                          v                          v
+----------------+        +----------------+        +----------------+
| Ciphertext 1   |        | Ciphertext 2   |        | Ciphertext 3   |      ...
+----------------+        +----------------+        +----------------+

*/


size_t AES_ECB_encrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    Block128* _SrcPtr = (Block128*)_Src;
    Block128* _KeyPtr = (Block128*)_Key;

    size_t _NewSize = _Size / 16, i = 0;
    for (; i < _NewSize; ++i)
        _DstPtr[i] = _aes_encrypt(_SrcPtr[i], _KeyPtr);
    if (_Size % 16)
        _DstPtr[i++] = _aes_encrypt(pkcs7_pad((unsigned char*)_Src, _Size), _KeyPtr);
    return i * 16;
}

/*

ECB (Electronic Codebook mode)

Decryption:

Ciphertext Block 1           Ciphertext Block 2           Ciphertext Block 3   ...
        |                          |                          |
        v                          v                          v
+----------------+        +----------------+        +----------------+
|  AES Decrypt   |        |  AES Decrypt   |        |  AES Decrypt   |      ...
|    (Key K)     |        |    (Key K)     |        |    (Key K)     |
+-------+--------+        +-------+--------+        +-------+--------+
        |                          |                          |
        v                          v                          v
+----------------+        +----------------+        +----------------+
| Plaintext 1    |        | Plaintext 2    |        | Plaintext 3    |      ...
+----------------+        +----------------+        +----------------+



*/


size_t AES_ECB_decrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    Block128* _SrcPtr = (Block128*)_Src;
    Block128* _KeyPtr = (Block128*)_Key;

    size_t _NewSize = _Size / 16;
    for (size_t i = 0; i < _NewSize; ++i)
        _DstPtr[i] = _aes_decrypt(_SrcPtr[i], _KeyPtr);
    return pkcs7_unpad((unsigned char*)_Dst, _Size);
}

/*

CBC(Cipher Block Chaining mode)

Encryption :

Plaintext Block 1         Plaintext Block 2         Plaintext Block 3   ...
        |                        |                        |
        v                        v                        v
+----------------+      +----------------+       +----------------+
|  XOR with IV   |      | XOR with       |       | XOR with       |
|                |      | Ciphertext 1   |       | Ciphertext 2   |
+-------+--------+      +-------+--------+       +-------+--------+
        |                        |                        |
        v                        v                        v
+----------------+      +----------------+       +----------------+
|  AES Encrypt   |      |  AES Encrypt   |       |  AES Encrypt   |
|    (Key K)     |      |    (Key K)     |       |    (Key K)     |
+-------+--------+      +-------+--------+       +-------+--------+
        |                        |                        |
        v                        v                        v
+----------------+      +----------------+       +----------------+
| Ciphertext 1   |      | Ciphertext 2   |       | Ciphertext 3   |
+----------------+      +----------------+       +----------------+


*/

size_t AES_CBC_encrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    Block128* _SrcPtr = (Block128*)_Src;
    Block128* _KeyPtr = (Block128*)_Key;

    _Seed(clock());
    *_DstPtr = random_message();
    ++_DstPtr;
    size_t _NewSize = _Size / 16, i = 0;
    for (; i < _NewSize; ++i)
        _DstPtr[i] = _aes_encrypt(_XorBlock128(_SrcPtr[i], *(_DstPtr + i - 1)), _KeyPtr);
    if (_Size % 16)
        _DstPtr[i++] = _aes_encrypt(_XorBlock128(pkcs7_pad((unsigned char*)_Src, _Size), *(_DstPtr + i - 1)), _KeyPtr);
    return (i + 1) * 16;
}

/*

CBC (Cipher Block Chaining mode)

Decryption:

IV = Ciphertext Block 0;

Ciphertext Block 1         Ciphertext Block 2         Ciphertext Block 3   ...
        |                        |                        |
        v                        v                        v
+----------------+      +----------------+       +----------------+
|  AES Decrypt   |      |  AES Decrypt   |       |  AES Decrypt   |
|    (Key K)     |      |    (Key K)     |       |    (Key K)     |
+-------+--------+      +-------+--------+       +-------+--------+
        |                        |                        |
        v                        v                        v
+----------------+      +----------------+       +----------------+
| XOR with IV    |      | XOR with       |       | XOR with       |
|                |      | Ciphertext 1   |       | Ciphertext 2   |
+-------+--------+      +-------+--------+       +-------+--------+
        |                        |                        |
        v                        v                        v
+----------------+      +----------------+       +----------------+
| Plaintext 1    |      | Plaintext 2    |       | Plaintext 3    |
+----------------+      +----------------+       +----------------+


*/

size_t AES_CBC_decrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    Block128* _SrcPtr = (Block128*)_Src;
    Block128* _KeyPtr = (Block128*)_Key;

    ++_SrcPtr;
    size_t _NewSize = _Size / 16 - 1;
    for (size_t i = 0; i < _NewSize; ++i)
        _DstPtr[i] = _XorBlock128(_aes_decrypt(_SrcPtr[i], _KeyPtr), *(_SrcPtr + i - 1));
    return pkcs7_unpad((unsigned char*)_Dst, _NewSize * 16);
}

size_t AES_OFB_encrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    Block128* _KeyPtr = (Block128*)_Key;

    _Seed(clock());
    _DstPtr[0] = random_message();
    size_t _NewSize = _Size / 16 + 1, i = 1;
    for (; i < _NewSize; ++i)
        _DstPtr[i] = _aes_encrypt(_DstPtr[i - 1], _KeyPtr);
    if (_Size % 16)
        _DstPtr[i++] = _XorBlock128(_aes_encrypt(_DstPtr[i - 1], _KeyPtr), pkcs7_pad((unsigned char*)_Src, _Size));
    array_xor((size_t*)(_DstPtr + 1), (size_t*)_Src, (_NewSize - 1) * 2);
    return i * 16;
}

size_t AES_OFB_decrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    Block128* _SrcPtr = (Block128*)_Src;
    Block128* _KeyPtr = (Block128*)_Key;

    size_t _NewSize = _Size / 16 - 1; // for not counting the IV
    _DstPtr[0] = _aes_encrypt(_SrcPtr[0], _KeyPtr);
    for (size_t i = 1; i < _NewSize; ++i)
        _DstPtr[i] = _aes_encrypt(_DstPtr[i - 1], _KeyPtr);
    array_xor((size_t*)_DstPtr, (size_t*)(_SrcPtr + 1), _NewSize * 2);
    return pkcs7_unpad((unsigned char*)_Dst, _NewSize * 16);
}

size_t AES_CFB_encrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    Block128* _SrcPtr = (Block128*)_Src;
    Block128* _KeyPtr = (Block128*)_Key;
    _Seed(clock());
    _DstPtr[0] = random_message(); ++_DstPtr;

    size_t _NewSize = _Size / 16, i = 0;
    for (; i < _NewSize; ++i)
        _DstPtr[i] = _XorBlock128(_aes_encrypt(*(_DstPtr + i - 1), _KeyPtr), _SrcPtr[i]);
    if (_Size % 16)
        _DstPtr[i++] = _XorBlock128(_aes_encrypt(*(_DstPtr + i - 1), _KeyPtr), pkcs7_pad((unsigned char*)_Src, _Size));
    return (i + 1) * 16;
}

size_t AES_CFB_decrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    Block128* _SrcPtr = (Block128*)_Src;
    Block128* _KeyPtr = (Block128*)_Key;

    size_t _NewSize = _Size / 16 - 1; ++_SrcPtr;
    for (size_t i = 0; i < _NewSize; ++i)
        _DstPtr[i] = _aes_encrypt(*(_SrcPtr + i - 1), _KeyPtr);
    array_xor((size_t*)_DstPtr, (size_t*)_SrcPtr, _NewSize * 2);
    return pkcs7_unpad((unsigned char*)_Dst, _NewSize * 16);
}

Block128 increment(Block128 ctr) {
    for (int i = 15; i >= 0; i--)
        if (++ctr.cells[i] != 0) break;
    return ctr;
}

size_t AES_CTR_encrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    Block128* _SrcPtr = (Block128*)_Src;
    Block128* _KeyPtr = (Block128*)_Key;
    _Seed(clock());
    Block128 ctr = random_message();
    _DstPtr[0] = ctr;

    size_t _NewSize = _Size / 16 + 1, i = 1;
    for (; i < _NewSize; ++i) {
        ctr = increment(ctr);
        _DstPtr[i] = _XorBlock128(_aes_encrypt(ctr, _KeyPtr), _SrcPtr[i - 1]);
    }
    if (_Size % 16) {
        ctr = increment(ctr);
        _DstPtr[i++] = _XorBlock128(_aes_encrypt(ctr, _KeyPtr), pkcs7_pad((unsigned char*)_Src, _Size));
    }
    return i * 16;
}

size_t AES_CTR_decrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key) {
    Block128* _DstPtr = (Block128*)_Dst;
    Block128* _SrcPtr = (Block128*)_Src;
    Block128* _KeyPtr = (Block128*)_Key;
    Block128 ctr = _SrcPtr[0];

    size_t _NewSize = _Size / 16 - 1; ++_SrcPtr;

    for (size_t i = 0; i < _NewSize; ++i) {
        ctr = increment(ctr);
        _DstPtr[i] = _XorBlock128(_aes_encrypt(ctr, _KeyPtr), _SrcPtr[i]);
    }
    return pkcs7_unpad((unsigned char*)_Dst, _NewSize * 16);
}



typedef enum { ECB, CBC, OFB, CFB, CTR } AES_MODE;

size_t AES_encrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key, AES_MODE _mode) {
    switch (_mode) {
    case ECB:
        return AES_ECB_encrypt(_Dst, _Src, _Size, _Key);
    case CBC:
        return AES_CBC_encrypt(_Dst, _Src, _Size, _Key);
    case OFB:
        return AES_OFB_encrypt(_Dst, _Src, _Size, _Key);
    case CFB:
        return AES_CFB_encrypt(_Dst, _Src, _Size, _Key);
    case CTR:
        return AES_CTR_encrypt(_Dst, _Src, _Size, _Key);
    default:
        fprintf(stderr, "Warning: Unknown encryption mode. Defaulting to ECB.\n");
        return AES_ECB_encrypt(_Dst, _Src, _Size, _Key);
    }
}

size_t AES_decrypt(void* _Dst, const void* _Src, size_t _Size, const void* _Key, AES_MODE _mode) {
    switch (_mode) {
    case ECB:
        return AES_ECB_decrypt(_Dst, _Src, _Size, _Key);
    case CBC:
        return AES_CBC_decrypt(_Dst, _Src, _Size, _Key);
    case OFB:
        return AES_OFB_decrypt(_Dst, _Src, _Size, _Key);
    case CFB:
        return AES_CFB_decrypt(_Dst, _Src, _Size, _Key);
    case CTR:
        return AES_CTR_decrypt(_Dst, _Src, _Size, _Key);
    default:
        fprintf(stderr, "Warning: Unknown decryption mode. Defaulting to ECB.\n");
        return AES_ECB_decrypt(_Dst, _Src, _Size, _Key);
    }
}



#endif