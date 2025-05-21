# CSE 130 - Introduction to Cryptography

This repository contains my implementations and solutions for the Introduction to Cryptography course (CSE 130) at UC Merced. At the time of attendance, this was the first semester this course was offered.

## Projects Overview

### Lab 01 - Cryptanalysis of XOR Cipher

Implementation of a cryptanalysis tool to break a repeating-key XOR cipher. The program uses frequency analysis and statistical methods to decrypt a ciphertext without knowing the key.

**Key Features:**
- Automated key length detection
- Frequency analysis for candidate key bytes
- Dictionary-based validation using common English words
- Converts hex-encoded ciphertext to plaintext

**Files:**
- `decrypt.c` - The main decryption algorithm implementation
- `ciphertext.txt` - Encrypted message for decryption
- `Lab01_Instructions.pdf` - Assignment details

**Technologies:**
- C programming language
- Statistical cryptanalysis techniques

### Lab 02 - Block Cipher Modes of Operation

Implementation of various AES block cipher modes of operation (ECB, CBC, OFB, CTR) and analysis of their security properties through image encryption.

**Key Features:**
- Implementation of four encryption modes:
  - Electronic Codebook (ECB)
  - Cipher Block Chaining (CBC)
  - Output Feedback (OFB)
  - Counter (CTR)
- Bit error propagation analysis
- Visual comparison of encryption patterns in images

**Files:**
- `main.py` - Implementation of encryption/decryption functions
- `test_image.bmp` - Test image for encryption
- `output/` - Directory containing encrypted, decrypted, and corrupted images

**Technologies:**
- Python
- PyCryptodome library for AES implementation
- PIL/Pillow for image processing

## Running the Code

### Lab 01
```bash
# Compile the decryption tool
gcc -o decrypt decrypt.c -lm

# Run the program on the provided ciphertext
./decrypt ciphertext.txt
```

### Lab 02
```bash
# Install required packages
pip install pycryptodome Pillow

# Run the encryption modes demo
python main.py
```

## Results

The `output` directory contains the results of Lab 02, showing how different encryption modes affect image data and handle corruption.

## License

This project is for educational purposes only. All implementations are original, based on assignments from the CSE 130 course.

## Acknowledgements

These projects were completed as part of the Introduction to Cryptography course at UC Merced.
