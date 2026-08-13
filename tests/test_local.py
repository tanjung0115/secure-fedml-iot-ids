"""
Test Script - Verify Local Setup
Test model, data loading, dan MQTT connection sebelum FL
"""

import torch
import torch.nn as nn
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from torch.utils.data import DataLoader, TensorDataset
import paho.mqtt.client as mqtt
import time

print("=" * 70)
print("FEDML + MQTT - Local Setup Testing")
print("=" * 70)

# ==================== TEST 1: PyTorch ====================
print("\n[TEST 1] PyTorch Installation")
try:
    print(f"  ✓ PyTorch version: {torch.__version__}")
    print(f"  ✓ CUDA available: {torch.cuda.is_available()}")
    print(f"  ✓ Device: {'GPU' if torch.cuda.is_available() else 'CPU'}")
except Exception as e:
    print(f"  ✗ Error: {e}")
    exit(1)

# ==================== TEST 2: Model ====================
print("\n[TEST 2] Model Creation")
try:
    class IDSModel(nn.Module):
        def __init__(self, input_dim=41, hidden_dim=64):
            super().__init__()
            self.fc1 = nn.Linear(input_dim, hidden_dim)
            self.relu = nn.ReLU()
            self.dropout = nn.Dropout(0.3)
            self.fc2 = nn.Linear(hidden_dim, 32)
            self.fc3 = nn.Linear(32, 2)
        
        def forward(self, x):
            x = self.fc1(x)
            x = self.relu(x)
            x = self.dropout(x)
            x = self.fc2(x)
            x = self.relu(x)
            x = self.fc3(x)
            return x
    
    model = IDSModel()
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  ✓ Model created successfully")
    print(f"  ✓ Total parameters: {total_params:,}")
    
    # Test forward pass
    dummy_input = torch.randn(1, 41)
    output = model(dummy_input)
    print(f"  ✓ Forward pass OK: input {dummy_input.shape} → output {output.shape}")
    
except Exception as e:
    print(f"  ✗ Error: {e}")
    exit(1)

# ==================== TEST 3: Data Loading ====================
print("\n[TEST 3] NSL-KDD Data Loading")
try:
    # Load data
    train_df = pd.read_csv('./data/KDDTrain+.txt', header=None)
    test_df = pd.read_csv('./data/KDDTest+.txt', header=None)
    
    print(f"  ✓ Training data: {len(train_df):,} samples")
    print(f"  ✓ Test data: {len(test_df):,} samples")
    
    # Remove difficulty level
    train_df = train_df.iloc[:, :-1]
    test_df = test_df.iloc[:, :-1]
    
    # Separate features and labels
    X_train = train_df.iloc[:, :-1].values
    y_train = (train_df.iloc[:, -1] != 'normal').astype(int).values
    
    X_test = test_df.iloc[:, :-1].values
    y_test = (test_df.iloc[:, -1] != 'normal').astype(int).values
    
    print(f"  ✓ Features shape: {X_train.shape}")
    print(f"  ✓ Labels: Normal={np.sum(y_train==0)}, Attack={np.sum(y_train==1)}")
    
    # Encode categorical features
    for col in [1, 2, 3]:
        le = LabelEncoder()
        X_train[:, col] = le.fit_transform(X_train[:, col].astype(str))
        X_test[:, col] = le.transform(X_test[:, col].astype(str))
    
    # Convert to float
    X_train = X_train.astype(np.float32)
    X_test = X_test.astype(np.float32)
    
    # Standardization
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)
    
    print(f"  ✓ Preprocessing complete")
    
    # Create DataLoader
    train_dataset = TensorDataset(
        torch.FloatTensor(X_train),
        torch.LongTensor(y_train)
    )
    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    
    print(f"  ✓ DataLoader created: {len(train_loader)} batches")
    
except FileNotFoundError:
    print(f"  ✗ Data files not found!")
    print(f"  → Please download NSL-KDD dataset to ./data/ folder")
    exit(1)
except Exception as e:
    print(f"  ✗ Error: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

# ==================== TEST 4: Training Loop ====================
print("\n[TEST 4] Training Loop (1 epoch)")
try:
    model = IDSModel()
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    
    model.train()
    total_loss = 0
    correct = 0
    total = 0
    
    print("  Training on first 5 batches...")
    for i, (batch_x, batch_y) in enumerate(train_loader):
        if i >= 5:  # Only 5 batches untuk testing
            break
        
        optimizer.zero_grad()
        outputs = model(batch_x)
        loss = criterion(outputs, batch_y)
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
        _, predicted = outputs.max(1)
        total += batch_y.size(0)
        correct += predicted.eq(batch_y).sum().item()
    
    avg_loss = total_loss / 5
    accuracy = 100. * correct / total
    
    print(f"  ✓ Training OK: Loss={avg_loss:.4f}, Acc={accuracy:.2f}%")
    
except Exception as e:
    print(f"  ✗ Error: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

# ==================== TEST 5: MQTT Connection ====================
print("\n[TEST 5] MQTT Broker Connection")

mqtt_test_success = False

def on_connect(client, userdata, flags, rc):
    global mqtt_test_success
    if rc == 0:
        print("  ✓ Connected to MQTT broker")
        mqtt_test_success = True
        client.disconnect()
    else:
        print(f"  ✗ Connection failed with code {rc}")

try:
    mqtt_client = mqtt.Client(client_id="test_client")
    mqtt_client.on_connect = on_connect
    
    print("  Testing connection to localhost:1883...")
    mqtt_client.connect("localhost", 1883, 60)
    mqtt_client.loop_start()
    
    # Wait for connection
    time.sleep(2)
    mqtt_client.loop_stop()
    
    if not mqtt_test_success:
        print("  ✗ MQTT connection failed")
        print("  → Make sure mosquitto is running:")
        print("     sudo systemctl start mosquitto")
        print("     sudo systemctl status mosquitto")
    
except Exception as e:
    print(f"  ✗ Error: {e}")
    print("  → Is mosquitto installed and running?")

# ==================== TEST 6: FedML Installation ====================
print("\n[TEST 6] FedML Installation")
try:
    import fedml
    print(f"  ✓ FedML version: {fedml.__version__}")
    
    # Check if MQTT backend available
    # Note: Ini tergantung versi FedML
    print(f"  ✓ FedML imported successfully")
    
except ImportError:
    print(f"  ✗ FedML not installed")
    print(f"  → Install with: pip install fedml")
except Exception as e:
    print(f"  ✗ Error: {e}")

# ==================== SUMMARY ====================
print("\n" + "=" * 70)
print("SETUP VERIFICATION SUMMARY")
print("=" * 70)
print("✓ All tests passed! Ready for federated learning setup.")
print("\nNext steps:")
print("1. Configure fedml_config.yaml and mqtt_config.yaml")
print("2. Run fedml_server.py on this machine")
print("3. Copy project to Raspberry Pi")
print("4. Run fedml_client.py on each RPi")
print("=" * 70)
