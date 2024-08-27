# AES Encryption Algorithm Implementation in C

![AES Logo](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#/media/File:AES_(Rijndael)_Round_Function.png)

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

- **Support for AES-128, AES-192, and AES-256**: Encrypt and decrypt data using various key sizes.
- **Efficient Implementation**: Optimized for performance with well-commented code.
- **Easy to Integrate**: Simple API for integration into your projects.

## 🚀 Getting Started

To get started with this implementation, you'll need to clone the repository and compile the code.

### Clone the Repository

```bash
git clone https://github.com/yourusername/aes-c.git
cd aes-c
gcc -o aes aes.c
```
## 📜 Usage
The repository includes example usage for encryption and decryption.
```C
#include "aes.h"

int main() {
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t plaintext[16] = "Encrypt this!";
    uint8_t ciphertext[16];
    uint8_t decryptedtext[16];

    AES_ECB_encrypt(plaintext, key, ciphertext, 16);
    AES_ECB_decrypt(ciphertext, key, decryptedtext, 16);

    printf("Ciphertext: ");
    for(int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
    printf("\nDecrypted: %s\n", decryptedtext);

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
[LinkedIn](https://www.linkedin.com/in/your-profile)
