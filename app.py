import streamlit as st
import pandas as pd
import hashlib
from cryptography.fernet import Fernet

st.title(" PQC Layer Simulation (Kyber + Dilithium)")
st.subheader("Simulated Post-Quantum Cryptography Encryption & Signature Verification")

# ---------- LOAD DATASET ----------
data = pd.read_csv("quantum_security_users.csv")
if 'role' not in data.columns:
    data['role'] = data['UserType'] if 'UserType' in data.columns else 'Patient'

# ---------- HELPER FUNCTIONS ----------
def generate_shared_secret(user_id, device, location):
    return hashlib.sha256(f"{user_id}{device}{location}".encode()).hexdigest()[:32]

def generate_signature(user_id, device, location, role):
    message = f"{user_id}{device}{location}_{role}"
    return hashlib.sha256(message.encode()).hexdigest()

def encrypt_data(data_str, shared_secret):
    key = hashlib.sha256(shared_secret.encode()).digest()[:32]
    fernet_key = Fernet(Fernet.generate_key())
    encrypted = fernet_key.encrypt(data_str.encode())
    return encrypted.decode()

# ---------- USER INPUT ----------
st.markdown("###  Enter User Details for Verification")
user_id_input = st.text_input("User ID (numeric)")
device_input = st.selectbox("Device Type", ["Mobile", "Laptop", "Tablet", "Desktop"])
location_input = st.selectbox("Login Location", ["northwest", "northeast", "southwest", "southeast"])

# ---------- SIMULATION ----------
if st.button("Run PQC Verification"):

    try:
        user_id_input = int(user_id_input)
    except:
        st.error("User ID must be a number")
        st.stop()

    # Find user in dataset
    user_record = data[data['UserID'] == user_id_input]
    if user_record.empty:
        st.error(f"No user found with UserID {user_id_input}")
        st.stop()

    user = user_record.iloc[0]

    # Prepare info
    patient_info = f"UserID:{user['UserID']}, Device:{device_input}, Location:{location_input}, Role:{user['role']}"

    # Generate shared secret and signature based on provided info
    shared_secret_enc = generate_shared_secret(user['UserID'], device_input, location_input)
    signature = generate_signature(user['UserID'], device_input, location_input, user['role'])

    # Verify each field
    mismatched_fields = []
    if device_input != user['Device']:
        mismatched_fields.append("Device")
    if location_input != user['Location']:
        mismatched_fields.append("Location")

    shared_secret_match = len(mismatched_fields) == 0
    signature_verified = len(mismatched_fields) == 0

    # Encrypt info
    encrypted_info = encrypt_data(patient_info, shared_secret_enc)

    # ---------- DISPLAY ----------
    st.subheader(f" Verification Result for UserID {user_id_input}")
    st.write(f"*Encrypted Info:* {encrypted_info}")
    st.write(f"*Shared Secret Match:* {'✅' if shared_secret_match else '❌'}")
    st.write(f"*Signature Verified:* {'✅' if signature_verified else '❌'}")

    if not shared_secret_match:
        st.write(f" Mismatched Fields: {', '.join(mismatched_fields)}")

    st.write(f"*Device Provided:* {device_input} | *Original Device:* {user['Device']}")
    st.write(f"*Location Provided:* {location_input} | *Original Location:* {user['Location']}")