import streamlit as st
import hashlib 
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Initialize session state variables if they don't exist
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # {"user_data_id": {"encrypted_text": "xyz", "passkey": "hashed", "salt": "random_salt"}}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = True  # Start as logged in

if 'data_list' not in st.session_state:
    st.session_state.data_list = []  # List of data IDs for retrieval

# Function to hash passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to derive key from passkey using PBKDF2
def derive_key(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Generate a new salt if not provided
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key, salt

# Function to encrypt data
def encrypt_data(text, passkey):
    # Derive a key from the passkey
    key, salt = derive_key(passkey)
    
    # Create a Fernet cipher with the derived key
    cipher = Fernet(key)
    
    # Encrypt the data
    encrypted_text = cipher.encrypt(text.encode()).decode()
    
    return encrypted_text, salt

# Function to decrypt data
def decrypt_data(encrypted_text, passkey, salt):
    try:
        # Derive the key from the passkey and stored salt
        key, _ = derive_key(passkey, salt)
        
        # Create a Fernet cipher with the derived key
        cipher = Fernet(key)
        
        # Decrypt the data
        decrypted_text = cipher.decrypt(encrypted_text.encode()).decode()
        
        return decrypted_text
    except Exception:
        # Decryption failed (wrong passkey)
        return None

# Generate a unique ID for the data
def generate_data_id():
    return hashlib.md5(os.urandom(16)).hexdigest()[:8]

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Check if user needs to login
if not st.session_state.logged_in:
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo, replace with proper auth
            st.session_state.failed_attempts = 0
            st.session_state.logged_in = True
            st.success("✅ Reauthorized successfully!")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
else:
    # Navigation
    menu = ["Home", "Store Data", "Retrieve Data"]
    choice = st.sidebar.selectbox("Navigation", menu)

    if choice == "Home":
        st.subheader("🏠 Welcome to the Secure Data System")
        st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
        
        # Display stored data count
        stored_count = len(st.session_state.stored_data)
        st.info(f"📊 You currently have {stored_count} securely stored data entries.")

    elif choice == "Store Data":
        st.subheader("📂 Store Data Securely")
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                # Hash the passkey for storage
                hashed_passkey = hash_passkey(passkey)
                
                # Encrypt the data
                encrypted_text, salt = encrypt_data(user_data, passkey)
                
                # Generate a unique ID
                data_id = generate_data_id()
                
                # Store in session state
                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_text, 
                    "passkey": hashed_passkey,
                    "salt": salt
                }
                
                # Update the data list
                st.session_state.data_list.append(data_id)
                
                st.success(f"✅ Data stored securely! Your Data ID: **{data_id}**")
                st.info("⚠️ Keep your Data ID and passkey safe. You'll need both to retrieve your data.")
            else:
                st.error("⚠️ Both fields are required!")

    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Your Data")
        
        # Create a selection widget if there's data
        if st.session_state.data_list:
            data_options = st.session_state.data_list
            selected_data = st.selectbox("Select Data ID:", data_options)
        else:
            st.warning("No data stored yet. Please store some data first.")
            selected_data = None
            
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt") and selected_data:
            if passkey:
                # Get the stored data
                stored_item = st.session_state.stored_data.get(selected_data)
                
                if stored_item:
                    # Check if the passkey hash matches
                    if hash_passkey(passkey) == stored_item["passkey"]:
                        # Decrypt the data
                        decrypted_text = decrypt_data(
                            stored_item["encrypted_text"], 
                            passkey, 
                            stored_item["salt"]
                        )
                        
                        if decrypted_text:
                            st.success("✅ Decryption successful!")
                            st.write("**Your decrypted data:**")
                            st.code(decrypted_text)
                            st.session_state.failed_attempts = 0
                        else:
                            st.session_state.failed_attempts += 1
                            st.error(f"❌ Decryption failed! Attempts remaining: {3 - st.session_state.failed_attempts}")
                    else:
                        st.session_state.failed_attempts += 1
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                else:
                    st.error("❌ Data not found!")
            else:
                st.error("⚠️ Passkey is required!")
                
            # Check if maximum attempts reached
            if st.session_state.failed_attempts >= 3:
                st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                st.session_state.logged_in = False
                st.experimental_rerun()

# Show failed attempts status in sidebar
if st.session_state.failed_attempts > 0:
    st.sidebar.warning(f"⚠️ Failed attempts: {st.session_state.failed_attempts}/3")