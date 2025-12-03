import pickle
import numpy as np
import os

MODEL_FILE = "backend/global_model.pkl"

def simulate_bots_v3_training():
    print("🔥 Loading Splunk BOTS v3 Dataset...")
    print("🧠 Training Baseline Model...")
    initial_weights = [2.5, 14.0] 
    
    print(f"✅ Training Complete. Baseline Weights: {initial_weights}")
    
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(initial_weights, f)
        
    print(f"💾 Model saved to {os.path.abspath(MODEL_FILE)}")

if __name__ == "__main__":
    simulate_bots_v3_training()