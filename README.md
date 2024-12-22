import datetime
import hashlib
import base64
from cryptography.fernet import Fernet
import logging

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Timestamp Generator
def generate_timestamp():
    return datetime.datetime.now().strftime("%d/%m/%Y")

# Hubble Telescope Data
class HubbleSpaceTelescope:
    def __init__(self):
        self.data = {
            "name": "Hubble Space Telescope",
            "launch_date": "24/04/1990",
            "country": "United States",
            "agency": "NASA",
            "achievements": [
                "Deep field imaging",
                "Discovery of exoplanets",
                "Confirmation of dark energy"
            ],
            "scientists": ["Edwin Hubble", "Lyman Spitzer"]
        }

    def get_summary(self):
        return self.data

# Counting Operations
def count_letters(input_string):
    counts = {}
    for char in input_string:
        if char.isalpha():
            counts[char] = counts.get(char, 0) + 1
    return counts

# Encryption and Decryption
class SecureData:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def encrypt(self, message: str):
        encrypted_text = self.cipher_suite.encrypt(message.encode())
        return base64.urlsafe_b64encode(encrypted_text).decode()

    def decrypt(self, encrypted_message: str):
        decoded_message = base64.urlsafe_b64decode(encrypted_message)
        return self.cipher_suite.decrypt(decoded_message).decode()

# Dual Code Verification
class DualCodeVerification:
    def __init__(self):
        self.secret_key = "SuperSecretKey"

    def generate_hash(self, data: str):
        return hashlib.sha256((data + self.secret_key).encode()).hexdigest()

    def verify_hash(self, data: str, hash_value: str):
        return self.generate_hash(data) == hash_value

# Main Functionality
if __name__ == "__main__":
    # Timestamp generation
    logging.info("Timestamp: " + generate_timestamp())

    # Hubble Telescope data
    telescope = HubbleSpaceTelescope()
    logging.info("Hubble Telescope Data: " + str(telescope.get_summary()))

    # Counting operation
    sample_text = "Hubble Space Telescope United States America NASA"
    counts = count_letters(sample_text)
    logging.info("Letter Counts: " + str(counts))

    # Encryption and decryption
    secure_data = SecureData()
    message = "Hubble Telescope"
    encrypted_message = secure_data.encrypt(message)
    decrypted_message = secure_data.decrypt(encrypted_message)
    logging.info(f"Encrypted: {encrypted_message}")
    logging.info(f"Decrypted: {decrypted_message}")

    # Dual-code verification
    verifier = DualCodeVerification()
    data = "Hubble Space Telescope"
    hash_value = verifier.generate_hash(data)
    logging.info(f"Hash Generated: {hash_value}")
    is_valid = verifier.verify_hash(data, hash_value)
    logging.info(f"Verification Successful: {is_valid}")
