import os
import base64
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# Initial Encryption Algorithm
class InitialEncryption:
    @staticmethod
    def encrypt(text):
        ciphertext = ""
        for char in text:
            if char.isalpha():  # Shift letters
                offset = 45 if char.isupper() else -45
                ciphertext += chr((ord(char) + offset - ord('A' if char.isupper() else 'a')) % 26 + ord('A' if char.isupper() else 'a'))
            elif char.isdigit():  # Transform digits
                ciphertext += str((int(char) * 3 + 7) % 10)
            else:  # Leave special characters unchanged
                ciphertext += char
        return ciphertext

    @staticmethod
    def decrypt(text):
        plaintext = ""
        for char in text:
            if char.isalpha():  # Reverse shift letters
                offset = -45 if char.isupper() else 45
                plaintext += chr((ord(char) + offset - ord('A' if char.isupper() else 'a')) % 26 + ord('A' if char.isupper() else 'a'))
            elif char.isdigit():  # Reverse digit transformation
                plaintext += str((int(char) - 7) * 7 % 10)
            else:  # Leave special characters unchanged
                plaintext += char
        return plaintext


# AES Handler
class AESHandler:
    def __init__(self, key=None):
        self.key = key or get_random_bytes(16)  # 128-bit key

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt(self, encrypted):
        data = base64.b64decode(encrypted)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    def get_key(self):
        return self.key


# RSA Handler
class RSAHandler:
    def __init__(self):
        (self.public_key, self.private_key) = rsa.newkeys(1024)

    def encrypt_key(self, aes_key):
        return base64.b64encode(rsa.encrypt(aes_key, self.public_key)).decode('utf-8')

    def decrypt_key(self, encrypted_key):
        return rsa.decrypt(base64.b64decode(encrypted_key), self.private_key)


# Hybrid Cryptographic Algorithm
class HybridCryptographicAlgorithm:
    def __init__(self):
        self.aes_handler = AESHandler()
        self.rsa_handler = RSAHandler()

    def encrypt(self, plaintext):
        # Step 1: Initial encryption
        initial_encrypted = InitialEncryption.encrypt(plaintext)
        # Step 2: AES encryption
        aes_encrypted = self.aes_handler.encrypt(initial_encrypted)
        # Step 3: RSA encryption for AES key
        encrypted_key = self.rsa_handler.encrypt_key(self.aes_handler.get_key())
        return encrypted_key + "::" + aes_encrypted

    def decrypt(self, encrypted):
        try:
            encrypted_key, aes_encrypted = encrypted.split("::")
            # Step 1: RSA decryption for AES key
            aes_key = self.rsa_handler.decrypt_key(encrypted_key.encode('utf-8'))
            # Step 2: AES decryption
            aes_handler = AESHandler(key=aes_key)
            aes_decrypted = aes_handler.decrypt(aes_encrypted)
            # Step 3: Reverse initial encryption
            return InitialEncryption.decrypt(aes_decrypted)
        except Exception as e:
            raise ValueError("Decryption failed: " + str(e))


# Main Application
class HybridCryptoApp:
    def __init__(self):
        self.hybrid_crypto = HybridCryptographicAlgorithm()

    def encrypt_text(self, plaintext):
        return self.hybrid_crypto.encrypt(plaintext)

    def decrypt_text(self, encrypted):
        return self.hybrid_crypto.decrypt(encrypted)


# Run the application
if __name__ == "__main__":
    app = HybridCryptoApp()

    while True:
        print("\nHybrid Cryptographic System")
        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == '1':
            plaintext = input("Enter the text to encrypt: ").strip()
            encrypted_text = app.encrypt_text(plaintext)
            print("\nEncrypted Text:")
            print(encrypted_text)

        elif choice == '2':
            encrypted = input("Enter the text to decrypt: ").strip()
            try:
                decrypted_text = app.decrypt_text(encrypted)
                print("\nDecrypted Text:")
                print(decrypted_text)
            except Exception as e:
                print("\nError during decryption:", str(e))

        elif choice == '3':
            print("Exiting the application. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")
