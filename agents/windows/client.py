import json
import time
import requests
import pickle
import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import IsolationForest 
# Using Isolation Forest as a lightweight "Autoencoder" substitute for demo simplicity
# You can replace this with Keras LSTM if you have TensorFlow installed

# === CONFIGURATION ===
SERVER_URL = "http://localhost:5000"  # Change to Master PC IP
CLIENT_ID = "Client-PC-01"
LOGS_PATH = r"C:\FLARE-data\Logs\logs.json"

def load_and_preprocess_logs():
    """Reads the JSON logs produced by the PowerShell Agent"""
    try:
        with open(LOGS_PATH, 'r') as f:
            data = json.load(f)
        
        if not data:
            return None

        df = pd.DataFrame(data)
        
        # FEATURE ENGINEERING (The "Pattern Recognition" part)
        # We convert 'LogonType' (2, 3, 10) into patterns
        # We convert 'Status' (Authorized/Unauthorized) into numbers
        
        # Simple encoding for demo
        features = df[['LogonType', 'EventID']].astype(int)
        return features.values
    except Exception as e:
        print(f"Error reading logs: {e}")
        return None

def train_local_model():
    print(f"[{CLIENT_ID}] 📂 Reading Local Logs...")
    X_train = load_and_preprocess_logs()
    
    if X_train is None or len(X_train) < 5:
        print("Not enough data to train yet...")
        return

    print(f"[{CLIENT_ID}] 🧠 Training Local Model (Federated)...")
    
    # Simulate Model Training
    # In real FL, we would load the 'Global Model' first, then train on top.
    model = IsolationForest(contamination=0.1)
    model.fit(X_train)
    
    # Extract "Weights" 
    # (For Isolation Forest, we simulate weights as the tree structure or support vectors)
    # For this demo, we create dummy weight arrays to prove the communication works
    dummy_weights = [np.random.rand(10, 10), np.random.rand(5)]
    
    # Upload Weights to Master
    print(f"[{CLIENT_ID}] 🚀 Sending Model Updates to Master...")
    payload = {
        'client_id': CLIENT_ID,
        'weights': dummy_weights
    }
    
    try:
        requests.post(f"{SERVER_URL}/upload_update", data=pickle.dumps(payload))
        print("✅ Update Sent Successfully!")
        
        # CHECK FOR ANOMALIES (Simulated)
        # If the model finds something weird, we send an ALERT, not the data
        anomalies = model.predict(X_train)
        if -1 in anomalies:
            send_alert("Detected unusual Logon Pattern (Type 10 at 3 AM)")
            
    except Exception as e:
        print(f"❌ Failed to reach Master Server: {e}")

def send_alert(msg):
    alert = {"client_id": CLIENT_ID, "message": msg}
    requests.post(f"{SERVER_URL}/alert", json=alert)
    print("🚨 Alert sent to Dashboard.")

if __name__ == "__main__":
    while True:
        train_local_model()
        print("💤 Sleeping for 30 seconds...")
        time.sleep(30)