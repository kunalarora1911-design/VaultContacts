
import csv
import os
import getpass
import bcrypt
from cryptography.fernet import Fernet

# -------------------------
# File paths
# -------------------------
USERS_FILE = "users.csv"
CONTACTS_FILE = "contacts.csv"
KEY_FILE = "secret.key"

# -------------------------
# Initialize files and key
# -------------------------
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Username", "Password"])

if not os.path.exists(CONTACTS_FILE):
    with open(CONTACTS_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Username", "Name", "Phone", "Email"])

# Generate or load encryption key
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(KEY_FILE, "rb") as f:
        key = f.read()

fernet = Fernet(key)

# -------------------------
# Helper Functions
# -------------------------
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def encrypt(data):
    return fernet.encrypt(data.encode()).decode()

def decrypt(data):
    return fernet.decrypt(data.encode()).decode()

def get_menu_choice():
    choice = input("Choose an option: ").strip()
    if not choice.isdigit():
        return None
    return int(choice)

def get_valid_name(prompt="Name: "):
    while True:
        name = input(prompt).strip()
        if name and all(c.isalpha() or c.isspace() for c in name):
            return name.title()
        print("❌ Invalid name. Use letters only.")

def get_valid_phone(prompt="Phone: "):
    while True:
        phone = input(prompt).strip()
        if phone.isdigit() and len(phone) >= 7:
            return phone
        print("❌ Invalid phone number.")

def get_valid_email(prompt="Email: "):
    while True:
        email = input(prompt).strip()
        if "@" in email and "." in email:
            return email
        print("❌ Invalid email format.")

# -------------------------
# Authentication
# -------------------------
def register_user():
    print("\n📝 Register")
    username = input("Username: ").strip()
    if not username:
        print("❌ Username cannot be empty")
        return

    with open(USERS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("Username") == username:
                print("❌ Username already exists")
                return

    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm Password: ")

    if password != confirm:
        print("❌ Passwords do not match")
        return

    if len(password) < 4:
        print("❌ Password must be at least 4 characters")
        return

    hashed = hash_password(password)
    with open(USERS_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([username, hashed])

    print("✅ Registration successful!")

def login_user():
    print("\n🔑 Login")
    attempts = 3
    while attempts > 0:
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")

        with open(USERS_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("Username") == username and check_password(password, row.get("Password")):
                    print(f"✅ Login successful! Welcome, {username}")
                    return username

        attempts -= 1
        print(f"❌ Invalid credentials. Attempts left: {attempts}")

    print("🚫 Too many failed attempts. Exiting.")
    return None

def auth_menu():
    while True:
        print("\n🔐 Authentication Menu")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            register_user()
        elif choice == "2":
            user = login_user()
            if user:
                main(user)
        elif choice == "3":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice")

# -------------------------
# Contact Management
# -------------------------
def add_contact(username):
    print("\n➕ Add Contact")
    name = get_valid_name()
    phone = get_valid_phone()
    email = get_valid_email()

    contacts = []
    with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("Username") and row.get("Name"):
                contacts.append(row)

    for row in contacts:
        if row["Username"] == username and decrypt(row["Name"]).lower() == name.lower():
            print("❌ Contact name already exists!")
            return

    with open(CONTACTS_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Username", "Name", "Phone", "Email"])
        writer.writerow({
            "Username": username,
            "Name": encrypt(name),
            "Phone": encrypt(phone),
            "Email": encrypt(email)
        })

    print("✅ Contact added!")

def view_contacts(username):
    print("\n📇 Your Contacts")
    found = False
    with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("Username") or not row.get("Name"):
                continue
            if row["Username"] == username:
                print(f"{decrypt(row['Name'])} | {decrypt(row['Phone'])} | {decrypt(row['Email'])}")
                found = True
    if not found:
        print("No contacts found!")

def search_contact(username):
    term = input("Enter name to search: ").strip().lower()
    found = False
    with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("Username") or not row.get("Name"):
                continue
            if row["Username"] == username and term in decrypt(row["Name"]).lower():
                print(f"{decrypt(row['Name'])} | {decrypt(row['Phone'])} | {decrypt(row['Email'])}")
                found = True
    if not found:
        print("❌ No matching contact found!")

def delete_contact(username):
    name_to_delete = input("Enter the contact name to delete: ").strip().lower()
    deleted = False
    contacts = []

    with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("Username") or not row.get("Name"):
                continue
            if row["Username"] == username and decrypt(row["Name"]).lower() == name_to_delete:
                deleted = True
                continue
            contacts.append(row)

    if not deleted:
        print("❌ Contact not found!")
        return

    with open(CONTACTS_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Username", "Name", "Phone", "Email"])
        writer.writeheader()
        writer.writerows(contacts)

    print("✅ Contact deleted successfully!")

def update_contact(username):
    name_to_update = input("Enter the contact name to update: ").strip().lower()
    updated = False
    contacts = []

    with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("Username") or not row.get("Name"):
                continue
            if row["Username"] == username and decrypt(row["Name"]).lower() == name_to_update:
                print(f"Found: {decrypt(row['Name'])} | {decrypt(row['Phone'])} | {decrypt(row['Email'])}")
                new_phone = input("New phone (Enter to keep old): ").strip()
                new_email = input("New email (Enter to keep old): ").strip()
                row["Phone"] = encrypt(new_phone) if new_phone else row["Phone"]
                row["Email"] = encrypt(new_email) if new_email else row["Email"]
                updated = True
            contacts.append(row)

    if not updated:
        print("❌ Contact not found!")
        return

    with open(CONTACTS_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Username", "Name", "Phone", "Email"])
        writer.writeheader()
        writer.writerows(contacts)

    print("✅ Contact updated successfully!")

# -------------------------
# Main Menu
# -------------------------
def main(username):
    while True:
        print(f"\n📙 Contact Book - User: {username}")
        print("1. Add Contact")
        print("2. View Contacts")
        print("3. Search Contact")
        print("4. Delete Contact")
        print("5. Update Contact")
        print("6. Logout")
        choice = get_menu_choice()
        if choice == 1:
            add_contact(username)
        elif choice == 2:
            view_contacts(username)
        elif choice == 3:
            search_contact(username)
        elif choice == 4:
            delete_contact(username)
        elif choice == 5:
            update_contact(username)
        elif choice == 6:
            print("👋 Logging out...")
            break
        else:
            print("❌ Invalid choice!")

# -------------------------
# Start Program
# -------------------------
if __name__ == "__main__":
    auth_menu()
