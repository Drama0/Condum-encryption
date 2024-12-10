CONDUM Encryption/Decryption Tool
CONDUM is a versatile encryption and decryption tool designed for secure file and text management. It uses a unique, grid-based key generation process (Condum key) and combines it with AES-GCM encryption for robust security.

Features
Custom Key Generation: Generate keys using a seed, number of layers, and evolution generations.
Secure Encryption: AES-256-GCM with randomly generated salts.
Cross-Platform Support: Works with both GUI and CLI.
File and Text Support: Encrypt/decrypt individual files or text messages.
Requirements
Python 3.8+
PyQt5 for the GUI
Cryptography library for encryption
Installation
Clone the repository: git clone https://github.com/DramaTv/condum-encryption.git cd condum-encryption

Install dependencies: pip install -r requirements.txt

Quick Example (CLI)
Encrypt a file: python condum_secure_cli.py

Follow prompts to create a key and encrypt a file
Decrypt the file: python condum_secure_cli.py

Use the same key and remember the original file format
Additional Notes
When decrypting a file, the original file format of the encrypted file must be remembered (e.g., .html, .jpg, .txt).

Molṑn labé – Resilient, Secure, Uncompromising.