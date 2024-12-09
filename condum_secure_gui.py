import os
import sys
import numpy as np
from collections import Counter
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QVBoxLayout, 
                             QFileDialog, QMessageBox, QInputDialog, QProgressDialog)
from PyQt5.QtCore import Qt

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

def generate_condum_key(seed, generations, layers, progress_dialog=None):
    random_seed_bytes = os.urandom(8)
    secure_random_seed = int.from_bytes(random_seed_bytes, 'big')
    combined_seed = (seed ^ secure_random_seed) % (2**32)

    np.random.seed(combined_seed)
    key_material = np.zeros(GRID_SIZE * GRID_SIZE * layers, dtype=np.uint8)

    for layer in range(layers):
        if progress_dialog and progress_dialog.wasCanceled():
            raise Exception("Key generation canceled by user.")
        grid = initialize_grid(GRID_SIZE)
        grid = evolve(grid, generations)
        key_material[layer * GRID_SIZE * GRID_SIZE:(layer + 1) * GRID_SIZE * GRID_SIZE] = grid.flatten()
        if progress_dialog:
            progress_dialog.setValue(layer + 1)

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

# ----- GUI Implementation -----
class CondumGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CONDUM Encryption/Decryption")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Create Key
        create_key_button = QPushButton("Create Key")
        create_key_button.clicked.connect(self.create_key_dialog)
        layout.addWidget(create_key_button)

        # Encrypt Text
        et_button = QPushButton("Encrypt Text")
        et_button.clicked.connect(self.encrypt_text_dialog)
        layout.addWidget(et_button)

        # Decrypt Text
        dt_button = QPushButton("Decrypt Text")
        dt_button.clicked.connect(self.decrypt_text_dialog)
        layout.addWidget(dt_button)

        # Encrypt File
        ef_button = QPushButton("Encrypt File")
        ef_button.clicked.connect(self.encrypt_file_dialog)
        layout.addWidget(ef_button)

        # Decrypt File
        df_button = QPushButton("Decrypt File")
        df_button.clicked.connect(self.decrypt_file_dialog)
        layout.addWidget(df_button)

        self.setLayout(layout)

    def create_key_dialog(self):
        seed_text, ok = QInputDialog.getText(self, "Seed", "Enter seed (0 to 2^64-1):")
        if not ok or not seed_text.strip():
            return

        try:
            seed = int(seed_text.strip())
            if seed < 0 or seed >= 2**64:
                raise ValueError("Seed must be between 0 and 2^64-1.")
        except ValueError as e:
            QMessageBox.warning(self, "Error", f"Invalid seed: {str(e)}")
            return

        generations, ok = QInputDialog.getInt(self, "Generations", f"Enter generations (max {MAX_GENERATIONS}):", 1, 1, MAX_GENERATIONS)
        if not ok:
            return
        layers, ok = QInputDialog.getInt(self, "Layers", f"Enter layers (max {MAX_LAYERS}):", 1, 1, MAX_LAYERS)
        if not ok:
            return

        progress_dialog = QProgressDialog("Generating key...", "Cancel", 0, layers, self)
        progress_dialog.setWindowModality(Qt.WindowModal)
        progress_dialog.setMinimumDuration(0)
        progress_dialog.setValue(0)

        try:
            condum_key = generate_condum_key(seed, generations, layers, progress_dialog)
            entropy = calculate_entropy(condum_key)
            QMessageBox.information(self, "Key Info", f"Condum Key Entropy: {entropy:.2f} bits/byte")

            save_path, _ = QFileDialog.getSaveFileName(self, "Save Key", "", "Key Files (*.key)")
            if save_path:
                save_key(save_path, condum_key)
                QMessageBox.information(self, "Success", f"Key saved to {save_path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to generate key: {str(e)}")
        finally:
            progress_dialog.close()

    def encrypt_text_dialog(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "Select Condum Key", "", "Key Files (*.key)")
        if not key_path:
            return

        try:
            condum_key = read_key(key_path)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error reading key: {str(e)}")
            return

        plaintext, ok = QInputDialog.getMultiLineText(self, "Plaintext", "Enter the message to encrypt:")
        if not ok or not plaintext.strip():
            return

        try:
            salt = os.urandom(32)  # Generate a random salt
            aes_key = derive_aes_key(condum_key, salt)
            encrypted_data = encrypt_data(plaintext.encode('utf-8'), aes_key)

            save_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted Message", "", "Encrypted Files (*.enc)")
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(salt)
                    f.write(encrypted_data)
                QMessageBox.information(self, "Success", f"Encrypted message saved to {save_path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Encryption failed: {str(e)}")

    def decrypt_text_dialog(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "Select Condum Key", "", "Key Files (*.key)")
        if not key_path:
            return

        try:
            condum_key = read_key(key_path)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error reading key: {str(e)}")
            return

        enc_path, _ = QFileDialog.getOpenFileName(self, "Select Encrypted Message", "", "Encrypted Files (*.enc)")
        if not enc_path:
            return

        try:
            with open(enc_path, 'rb') as f:
                salt = f.read(32)
                encrypted_data = f.read()

            aes_key = derive_aes_key(condum_key, salt)
            plaintext = decrypt_data(encrypted_data, aes_key).decode('utf-8')
            QMessageBox.information(self, "Decrypted Text", plaintext)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Decryption failed: {str(e)}")

    def encrypt_file_dialog(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "Select Condum Key", "", "Key Files (*.key)")
        if not key_path:
            return

        input_file, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if not input_file:
            return

        try:
            condum_key = read_key(key_path)
            with open(input_file, 'rb') as f:
                data = f.read()

            salt = os.urandom(32)
            aes_key = derive_aes_key(condum_key, salt)
            encrypted_data = encrypt_data(data, aes_key)

            save_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", "", "Encrypted Files (*.enc)")
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(salt)
                    f.write(encrypted_data)
                QMessageBox.information(self, "Success", f"Encrypted file saved to {save_path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Encryption failed: {str(e)}")

    def decrypt_file_dialog(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "Select Condum Key", "", "Key Files (*.key)")
        if not key_path:
            return

        enc_file, _ = QFileDialog.getOpenFileName(self, "Select Encrypted File", "", "Encrypted Files (*.enc)")
        if not enc_file:
            return

        try:
            condum_key = read_key(key_path)
            with open(enc_file, 'rb') as f:
                salt = f.read(32)
                encrypted_data = f.read()

            aes_key = derive_aes_key(condum_key, salt)
            plaintext = decrypt_data(encrypted_data, aes_key)

            save_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", "", "Decrypted Files (*.*)")
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(plaintext)
                QMessageBox.information(self, "Success", f"Decrypted file saved to {save_path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Decryption failed: {str(e)}")

# ----- Main Entry Point -----
def main():
    app = QApplication(sys.argv)
    gui = CondumGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
