#Password Manager using Cryptography
#Author : mohankumar[mobby14]

import base64
import secrets
import string
import sys
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class PasswordManager:
    def __init__(self):
        self.key_value = b'TheBestSecretKey'  # 16 bytes for AES-128
        self.password_store = {}

    def generate_strong_password(self, length=16, include_symbols=True, include_numbers=True, 
                                include_uppercase=True, include_lowercase=True):
        """Generate a cryptographically secure strong password"""
        if length < 8:
            length = 8  # Minimum secure length
            
        characters = ""
        if include_lowercase:
            characters += string.ascii_lowercase
        if include_uppercase:
            characters += string.ascii_uppercase
        if include_numbers:
            characters += string.digits
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            characters = string.ascii_letters + string.digits  # Fallback
        
        # Ensure at least one character from each selected category
        password = []
        if include_lowercase:
            password.append(secrets.choice(string.ascii_lowercase))
        if include_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if include_numbers:
            password.append(secrets.choice(string.digits))
        if include_symbols:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        
        # Fill the rest randomly
        for _ in range(length - len(password)):
            password.append(secrets.choice(characters))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)

    def check_password_strength(self, password):
        """Check password strength and return score and feedback"""
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters long")
        
        # Character variety checks
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
            
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
            
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Add numbers")
            
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        # Strength categories
        if score >= 6:
            strength = "Very Strong"
        elif score >= 4:
            strength = "Strong"
        elif score >= 3:
            strength = "Medium"
        elif score >= 2:
            strength = "Weak"
        else:
            strength = "Very Weak"
            
        return strength, score, feedback

    def add_password(self, site, password=None):
        """Add password with option to generate strong password"""
        try:
            if password is None:
                # Ask if user wants a generated password
                print(f"\n--- Adding password for: {site} ---")
                choice = input("Do you want a generated strong password? (y/n): ").lower().strip()
                
                if choice == 'y' or choice == 'yes':
                    # Get preferences for password generation
                    print("\nPassword Generation Options:")
                    try:
                        length = int(input("Password length (default 16): ") or "16")
                    except ValueError:
                        length = 16
                    
                    include_symbols = input("Include symbols? (Y/n): ").lower().strip() != 'n'
                    include_numbers = input("Include numbers? (Y/n): ").lower().strip() != 'n'
                    include_uppercase = input("Include uppercase? (Y/n): ").lower().strip() != 'n'
                    include_lowercase = input("Include lowercase? (Y/n): ").lower().strip() != 'n'
                    
                    # Generate multiple options
                    print(f"\nGenerated password options for {site}:")
                    passwords = []
                    for i in range(3):
                        gen_password = self.generate_strong_password(
                            length, include_symbols, include_numbers, 
                            include_uppercase, include_lowercase
                        )
                        passwords.append(gen_password)
                        strength, score, _ = self.check_password_strength(gen_password)
                        print(f"{i+1}. {gen_password} (Strength: {strength})")
                    
                    choice = input(f"\nSelect option (1-3) or enter 'c' for custom password: ").strip()
                    
                    if choice in ['1', '2', '3']:
                        password = passwords[int(choice) - 1]
                        print(f"Selected password: {password}")
                    else:
                        password = input("Enter your custom password: ")
                        strength, score, feedback = self.check_password_strength(password)
                        print(f"Password strength: {strength}")
                        if feedback:
                            print("Suggestions:", ", ".join(feedback))
                else:
                    password = input("Enter your password: ")
                    strength, score, feedback = self.check_password_strength(password)
                    print(f"Password strength: {strength}")
                    if feedback:
                        print("Suggestions:", ", ".join(feedback))
            
            encrypted_password = self.encrypt(password)
            self.password_store[site] = encrypted_password
            print("Password added successfully!")
            
        except Exception as e:
            print(f"Error: {e}")

    def get_password(self, site):
        try:
            encrypted_password = self.password_store.get(site)
            if encrypted_password is not None:
                return self.decrypt(encrypted_password)
            else:
                return "No password found for this site."
        except Exception as e:
            print(f"Error: {e}")
            return None

    def list_sites(self):
        """List all stored sites"""
        if not self.password_store:
            print("No passwords stored yet.")
        else:
            print("\nStored sites:")
            for i, site in enumerate(self.password_store.keys(), 1):
                print(f"{i}. {site}")

    def generate_password_only(self):
        """Generate password without storing"""
        print("\n--- Password Generator ---")
        try:
            length = int(input("Password length (default 16): ") or "16")
        except ValueError:
            length = 16
        
        include_symbols = input("Include symbols? (Y/n): ").lower().strip() != 'n'
        include_numbers = input("Include numbers? (Y/n): ").lower().strip() != 'n'
        include_uppercase = input("Include uppercase? (Y/n): ").lower().strip() != 'n'
        include_lowercase = input("Include lowercase? (Y/n): ").lower().strip() != 'n'
        
        print(f"\nGenerated passwords:")
        for i in range(5):
            gen_password = self.generate_strong_password(
                length, include_symbols, include_numbers, 
                include_uppercase, include_lowercase
            )
            strength, score, _ = self.check_password_strength(gen_password)
            print(f"{i+1}. {gen_password} (Strength: {strength})")

    def encrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key_value), modes.ECB())
        encryptor = cipher.encryptor()
        
        # Pad the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode('utf-8'))
        padded_data += padder.finalize()
        
        encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(encrypted_bytes).decode('utf-8')

    def decrypt(self, encrypted_data):
        cipher = Cipher(algorithms.AES(self.key_value), modes.ECB())
        decryptor = cipher.decryptor()
        
        decoded_data = base64.b64decode(encrypted_data.encode('utf-8'))
        decrypted_bytes = decryptor.update(decoded_data) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_bytes)
        unpadded_data += unpadder.finalize()
        
        return unpadded_data.decode('utf-8')


def main():
    print("=== Secure Password Manager ===")
    print("Features: AES Encryption + Strong Password Generator")
    
    manager = PasswordManager()
    
    while True:
        print("\n" + "="*40)
        print("1. Add Password (with generation option)")
        print("2. Retrieve Password")
        print("3. List All Sites")
        print("4. Generate Strong Password")
        print("5. Exit")
        print("="*40)
        
        try:
            choice = int(input("Choose an option: "))
        except ValueError:
            print("Invalid choice. Please enter a number.")
            continue

        if choice == 1:
            site = input("Enter site/service name: ").strip()
            if site:
                manager.add_password(site)
            else:
                print("Site name cannot be empty.")
                
        elif choice == 2:
            manager.list_sites()
            site = input("\nEnter site name: ").strip()
            if site:
                retrieved_password = manager.get_password(site)
                print(f"Password for {site}: {retrieved_password}")
            else:
                print("Site name cannot be empty.")
                
        elif choice == 3:
            manager.list_sites()
            
        elif choice == 4:
            manager.generate_password_only()
            
        elif choice == 5:
            print("Goodbye! Stay secure!")
            sys.exit(0)
            
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
