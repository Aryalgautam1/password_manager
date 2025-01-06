import random
import string
import pandas as pd
from cryptography.fernet import Fernet

FILENAME = "passwords.xlsx"
KEY_FILE = "secret.key"

# Generate and save a secret key
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

# Load the secret key
def load_key():
    try:
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print("Key file not found. Generating a new key...")
        generate_key()
        return load_key()

# Initialize the Fernet object
key = load_key()
cipher = Fernet(key)

def generate_password(length=12, include_uppercase=True, include_numbers=True, include_symbols=True):
    # Define character pools
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase if include_uppercase else ""
    numbers = string.digits if include_numbers else ""
    symbols = string.punctuation if include_symbols else ""

    # Combine all selected pools
    all_characters = lowercase + uppercase + numbers + symbols

    # Ensure there are characters to choose from
    if not all_characters:
        raise ValueError("No character sets selected! Please include at least one character set.")

    # Generate password
    password = ''.join(random.choice(all_characters) for _ in range(length))
    return password

def save_to_excel(data):
    try:
        existing_data = pd.read_excel(FILENAME)
        df = pd.concat([existing_data, pd.DataFrame(data)])
    except FileNotFoundError:
        df = pd.DataFrame(data)

    df.to_excel(FILENAME, index=False)
    print(f"Data saved to {FILENAME}")

def load_data():
    try:
        return pd.read_excel(FILENAME)
    except FileNotFoundError:
        return pd.DataFrame(columns=["Username", "Application", "Password"])

def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

def access_decrypted_password():
    data = load_data()
    if data.empty:
        print("No saved passwords found.")
        return

    print("\nSaved Entries:")
    print(data.drop(columns=["Password"]))  # Hide encrypted passwords

    username = input("Enter the username to access: ")
    app_name = input("Enter the application name: ")

    mask = (data["Username"] == username) & (data["Application"] == app_name)
    if mask.any():
        encrypted_password = data.loc[mask, "Password"].values[0]
        print(f"Decrypted password: {decrypt_password(encrypted_password)}")
    else:
        print("No matching entry found.")

def modify_password():
    data = load_data()
    if data.empty:
        print("No saved passwords found.")
        return

    print("\nSaved Entries:")
    print(data.drop(columns=["Password"]))  # Hide encrypted passwords

    username = input("Enter the username to modify: ")
    app_name = input("Enter the application name: ")

    mask = (data["Username"] == username) & (data["Application"] == app_name)
    if mask.any():
        new_password = input("Enter the new password: ")
        encrypted_password = encrypt_password(new_password)
        data.loc[mask, "Password"] = encrypted_password
        data.to_excel(FILENAME, index=False)
        print("Password updated successfully!")
    else:
        print("No matching entry found to modify.")

def main():
    print("Welcome to the Encrypted Password Manager!")
    while True:
        print("\nMenu:")
        print("1. Add a new password")
        print("2. Access a decrypted password")
        print("3. Modify an existing password")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ")
        if choice == "1":
            # Add a new password
            app_name = input("Enter the name of the software/website/application: ")
            username = input("Enter your username: ")
            length = int(input("Enter the desired password length (e.g., 12): "))
            include_uppercase = input("Include uppercase letters? (yes/no): ").lower() == "yes"
            include_numbers = input("Include numbers? (yes/no): ").lower() == "yes"
            include_symbols = input("Include symbols? (yes/no): ").lower() == "yes"

            # Generate and display 3 password options
            passwords = [generate_password(length, include_uppercase, include_numbers, include_symbols) for _ in range(3)]
            print("\nHere are your password suggestions:")
            for i, password in enumerate(passwords, 1):
                print(f"{i}: {password}")

            choice = int(input("\nEnter the number of the password you like (1-3): "))
            chosen_password = passwords[choice - 1]

            # Encrypt the chosen password
            encrypted_password = encrypt_password(chosen_password)

            # Save to Excel
            data = [{"Username": username, "Application": app_name, "Password": encrypted_password}]
            save_to_excel(data)

        elif choice == "2":
            # Access a decrypted password
            access_decrypted_password()

        elif choice == "3":
            # Modify an existing password
            modify_password()

        elif choice == "4":
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
