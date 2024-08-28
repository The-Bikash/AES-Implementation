# AES Encryption Algorithm Implementation in C

![AES Logo](https://github.com/user-attachments/assets/df36507f-0a8e-4f89-847d-43cfb4e785ea))

Welcome to the AES Encryption Algorithm Implementation repository! This project provides a complete implementation of the Advanced Encryption Standard (AES) in C. AES is a symmetric key encryption algorithm widely used to secure data.

## 📚 Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Examples](#examples)
- [License](#license)
- [Contributing](#contributing)
- [Contact](#contact)

## 🔥 Features

- **Support for AES-128**: Encrypt and decrypt data using 128 bit key size.
- **Efficient Implementation**: Optimized for performance with well-commented code.
- **Easy to Integrate**: Simple API for integration into your projects.

## 🚀 Getting Started

To get started with this implementation, you'll need to clone the repository and compile the code.

## 📜 Usage
The repository includes example usage for encryption and decryption.
```C
#include "aes.h"
#include "aes_modes.h"

#include <stdio.h>


int main() {

    Block128 user_key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    Block128 keys[11];
    gen_key_schedule_128(user_key, keys);

    unsigned char plaintext[] = "Encrypt this!";
    size_t plaintextsize = sizeof(plaintext);

    unsigned char ciphertext[100];
    size_t ciphertextsize = AES_ECB_encrypt(ciphertext, plaintext, plaintextsize, keys);

    unsigned char deciphertext[100];
    size_t deciphertextsize = AES_ECB_decrypt(deciphertext, ciphertext, ciphertextsize, keys);

    printf("Ciphertext: ");
    for (int i = 0; i < ciphertextsize; i++) printf("%02x ", ciphertext[i]);

    printf("\nDeciphertext: %s\n", deciphertext);
    return 0;

}
```
## 📝 License
This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing
Contributions are welcome! Feel free to fork this repository, create a new branch, and submit a pull request.

## 📞 Support
For any questions or issues, please open an issue on GitHub or contact me directly.

## 🌐 Connect with Me
[LinkedIn](www.linkedin.com/in/the-bikash)
