import pickle
import numpy as np
import os

# Ensure this matches where your Server looks for the file
# If running from Root: "backend/global_model.pkl"
# If running from backend/: "global_model.pkl"
MODEL_FILE = "backend/global_model.pkl" 

def simulate_unified_training():
    print("🔥 Loading FLARE Unified Datasets (Simulation)...")

    # ==========================================
    # 1. Simulate System Logs (Source 1)
    # ==========================================
    # Vector: [Source=1, Target=LogonType, Time=Hour, Size=0]
    print("   ↳ Generating Endpoint Data (BOTS v3)...")
    n_sys = 5000
    sys_src = np.ones(n_sys)
    sys_target = np.random.choice([2, 10, 5], size=n_sys) # Common Logon Types
    sys_time = np.random.randint(0, 24, size=n_sys)       # Activity throughout the day
    sys_size = np.zeros(n_sys)                            # Padding (Size is 0 for Sys)
    
    X_sys = np.column_stack((sys_src, sys_target, sys_time, sys_size))

    # ==========================================
    # 2. Simulate Network Logs (Source 2)
    # ==========================================
    # Vector: [Source=2, Target=Port, Time=Hour, Size=Bytes]
    print("   ↳ Generating Network Data (CICIDS2017)...")
    n_net = 5000
    net_src = np.full(n_net, 2)
    net_target = np.random.choice([80, 443, 53, 445], size=n_net) # Common Ports
    net_time = np.random.randint(0, 24, size=n_net)
    net_size = np.random.normal(500, 200, size=n_net)             # Packet Sizes
    # Ensure no negative sizes from normal distribution
    net_size = np.maximum(net_size, 0)

    X_net = np.column_stack((net_src, net_target, net_time, net_size))

    # ==========================================
    # 3. Fusion & Calculation
    # ==========================================
    print("⚗️  Fusing Endpoint & Network Data...")
    X_train = np.vstack((X_sys, X_net))

    # Calculate Baseline Weights (Centroid/Mean)
    # This aligns with what fl_client.py sends (np.mean)
    baseline_weights = np.mean(X_train, axis=0).tolist()

    print(f"✅ Training Complete.")
    print(f"   Dataset Size: {len(X_train)} events")
    print(f"   Vector Shape: 4 Dimensions [Source, Target, Time, Size]")
    print(f"   Baseline Weights: {baseline_weights}")
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(MODEL_FILE), exist_ok=True)

    with open(MODEL_FILE, "wb") as f:
        pickle.dump(baseline_weights, f)
        
    print(f"💾 Model saved to {os.path.abspath(MODEL_FILE)}")

if __name__ == "__main__":
    simulate_unified_training()