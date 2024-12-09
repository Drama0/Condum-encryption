import os
import sys
import numpy as np
from collections import Counter
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ----- Configuration Constants -----
GRID_SIZE = 100
MAX_GENERATIONS = 1000
MAX_LAYERS = 100

# ----- Core Functions -----
def calculate_entropy(key):
    """Calculate the entropy of the key in bits per byte."""
    from math import log2
    byte_counts = Counter(key)
    entropy = -sum((count / len(key)) * log2(count / len(key)) for count in byte_counts.values())
    return entropy

def initialize_grid(size):
    return np.random.randint(0, 256, size=(size, size), dtype=np.uint8)

def evolve(grid, generations):
    for _ in range(generations):
        padded_grid = np.pad(grid, pad_width=1, mode='wrap')
        neighbors = (
            padded_grid[:-2, :-2] + padded_grid[:-2, 1:-1] + padded_grid[:-2, 2:] +
            padded_grid[1:-1, :-2] + padded_grid[1:-1, 2:] +
            padded_grid[2:, :-2] + padded_grid[2:, 1:-1] + padded_grid[2:, 2:]
        )
        grid = (grid + neighbors) % 256
    return grid

def generate_condum_key(seed, generations, layers):
    random_seed_bytes = os.urandom(8)
    secure_random_seed = int.from_bytes(random_seed_bytes, 'big')
    combined_seed = (seed ^ secure_random_seed) % (2**32)

    np.random.seed(combined_seed)
    key_material = np.zeros(GRID_SIZE * GRID_SIZE * layers, dtype=np.uint8)

    for layer in range(layers):
        grid = initialize_grid(GRID_SIZE)
        grid = evolve(grid, generations)
        key_material[layer * GRID_SIZE * GRID_SIZE:(layer + 1) * GRID_SIZE * GRID_SIZE] = grid.flatten()

    return key_material

def derive_aes_key(condum_key, salt):
    """
    Derive a 256-bit AES key from the Condum key and a given salt.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"condum-key-derivation"
    )
    return hkdf.derive(condum_key.tobytes())

def save_key(filename, key_material):
    """
    Save the Condum key to a file in binary format.
    """
    with open(filename, 'wb') as file:
        file.write(key_material.tobytes())

def read_key(filename):
    """
    Read the Condum key from a file.
    """
    with open(filename, 'rb') as file:
        data = file.read()
    return np.frombuffer(data, dtype=np.uint8)

def encrypt_data(data, aes_key):
    """
    Encrypt binary data using AES-256-GCM.
    Returns nonce + ciphertext + tag.
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # recommended 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt_data(enc_data, aes_key):
    """
    Decrypt binary data using AES-256-GCM.
    Encrypted data should contain nonce + ciphertext + tag.
    """
    if len(enc_data) < 12:
        raise ValueError("Encrypted data is too short.")
    aesgcm = AESGCM(aes_key)
    nonce = enc_data[:12]
    ciphertext_with_tag = enc_data[12:]
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)

# ----- CLI Functions -----
def create_key_cli():
    seed = int(input("Enter seed (0 to 2^64-1): "))
    generations = int(input(f"Enter number of generations (max {MAX_GENERATIONS}): "))
    layers = int(input(f"Enter number of layers (max {MAX_LAYERS}): "))

    condum_key = generate_condum_key(seed, generations, layers)
    entropy = calculate_entropy(condum_key)
    print(f"Generated Condum Key with {entropy:.2f} bits/byte of entropy.")

    save_path = input("Enter file path to save the Condum key (e.g., mykey.key): ")
    save_key(save_path, condum_key)
    print(f"Key saved to {save_path}")

def encrypt_text_cli():
    key_path = input("Enter Condum key file path: ")
    condum_key = read_key(key_path)

    plaintext = input("Enter text to encrypt: ")
    salt = os.urandom(32)  # Generate a random salt
    aes_key = derive_aes_key(condum_key, salt)  # Derive AES key using the random salt
    encrypted_data = encrypt_data(plaintext.encode('utf-8'), aes_key)

    save_path = input("Enter file path to save encrypted text (e.g., encrypted.bin): ")
    with open(save_path, 'wb') as f:
        f.write(salt)  # Save salt
        f.write(encrypted_data)  # Save encrypted data
    print(f"Encrypted text saved to {save_path}")

def decrypt_text_cli():
    key_path = input("Enter Condum key file path: ")
    condum_key = read_key(key_path)

    enc_path = input("Enter file path of encrypted text (e.g., encrypted.bin): ")
    with open(enc_path, 'rb') as f:
        salt = f.read(32)  # Read the salt (first 32 bytes)
        encrypted_data = f.read()  # The rest is the encrypted data

    aes_key = derive_aes_key(condum_key, salt)  # Derive AES key using the salt
    plaintext = decrypt_data(encrypted_data, aes_key).decode('utf-8')
    print(f"Decrypted Text: {plaintext}")

def encrypt_file_cli():
    key_path = input("Enter Condum key file path: ")
    condum_key = read_key(key_path)

    input_file = input("Enter path of the file to encrypt: ")
    output_file = input("Enter output file path (e.g., file.enc): ")

    with open(input_file, 'rb') as f:
        data = f.read()

    salt = os.urandom(32)  # Generate a random salt
    aes_key = derive_aes_key(condum_key, salt)
    encrypted_data = encrypt_data(data, aes_key)

    with open(output_file, 'wb') as f:
        f.write(salt)  # Save salt
        f.write(encrypted_data)  # Save encrypted data
    print(f"Encrypted file saved to {output_file}")

def decrypt_file_cli():
    key_path = input("Enter Condum key file path: ")
    condum_key = read_key(key_path)

    enc_file = input("Enter path of the encrypted file: ")
    dec_file = input("Enter output path for the decrypted file: ")

    with open(enc_file, 'rb') as f:
        salt = f.read(32)  # Read the salt (first 32 bytes)
        encrypted_data = f.read()  # The rest is the encrypted data

    aes_key = derive_aes_key(condum_key, salt)
    plaintext = decrypt_data(encrypted_data, aes_key)

    with open(dec_file, 'wb') as f:
        f.write(plaintext)
    print(f"Decrypted file saved to {dec_file}")

# ----- Main CLI -----
def main():
    print("CONDUM Encryption/Decryption CLI")
    while True:
        print("\nOptions: ")
        print("1. Create Key")
        print("2. Encrypt Text")
        print("3. Decrypt Text")
        print("4. Encrypt File")
        print("5. Decrypt File")
        print("6. Exit")

        choice = input("Select an option: ").strip()
        if choice == "1":
            create_key_cli()
        elif choice == "2":
            encrypt_text_cli()
        elif choice == "3":
            decrypt_text_cli()
        elif choice == "4":
            encrypt_file_cli()
        elif choice == "5":
            decrypt_file_cli()
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
