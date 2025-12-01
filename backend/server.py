import numpy as np
from flask import Flask, request, jsonify
import pickle
import os

# === FLARE SERVER CONFIGURATION ===
app = Flask(__name__)
UPLOAD_FOLDER = 'global_model_storage'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# This mimics the "Global Model" (Weights)
# In a real scenario, this would be a loaded Keras/PyTorch model
global_weights = [] 
client_updates = []
ROUND_NUMBER = 1
MIN_CLIENTS_FOR_ROUND = 2  # Wait for 2 clients before averaging

@app.route('/')
def home():
    return "🔥 FLARE Global Aggregator Running"

@app.route('/upload_update', methods=['POST'])
def upload_update():
    """
    Clients send their LOCALLY trained model weights here.
    No raw logs are sent. Privacy is preserved.
    """
    global client_updates
    try:
        # Receive pickled weights
        client_data = pickle.loads(request.data)
        client_id = client_data['client_id']
        weights = client_data['weights']
        
        print(f"✅ Received update from Client: {client_id}")
        client_updates.append(weights)

        # Trigger Federated Averaging if we have enough updates
        if len(client_updates) >= MIN_CLIENTS_FOR_ROUND:
            perform_fed_avg()
            return jsonify({"status": "accepted", "message": "Round Complete - New Global Model Created"})
        
        return jsonify({"status": "accepted", "message": "Waiting for other clients..."})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_global_model', methods=['GET'])
def get_global_model():
    """Clients download the new smart model from here."""
    if not global_weights:
        return jsonify({"status": "not_ready"})
    
    # Serialize and return weights
    return pickle.dumps(global_weights)

@app.route('/alert', methods=['POST'])
def receive_alert():
    """
    Clients send NOTIFICATIONS here if an Anomaly is found.
    This populates the Dashboard.
    """
    alert_data = request.json
    print(f"🚨 ALERT from {alert_data['client_id']}: {alert_data['message']}")
    # Here you would save to MongoDB for the dashboard to read
    return jsonify({"status": "alert_received"})

def perform_fed_avg():
    """The Heart of Federated Learning: Average the weights"""
    global global_weights, client_updates, ROUND_NUMBER
    print(f"\n🔄 Performing FedAvg for Round {ROUND_NUMBER}...")
    
    # Mathematical Averaging of Weights
    # (Simplified: assumes all clients have same model structure)
    new_weights = [np.mean(layer, axis=0) for layer in zip(*client_updates)]
    global_weights = new_weights
    
    # Save model checkpoint
    with open(f'{UPLOAD_FOLDER}/global_model_r{ROUND_NUMBER}.pkl', 'wb') as f:
        pickle.dump(global_weights, f)
        
    print(f"✨ Global Model Updated! (Round {ROUND_NUMBER} Complete)")
    client_updates = []  # Reset for next round
    ROUND_NUMBER += 1

if __name__ == '__main__':
    print("=== FLARE Master Node Started ===")
    print("Waiting for Local Gradients from Clients...")
    app.run(host='0.0.0.0', port=5000)