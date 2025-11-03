import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import os

# -----------------------------------------------------------------
# --- Configuration ---
# -----------------------------------------------------------------
# Change this to 'Tuesday-WorkingHours.pcap_ISCX.csv' or another file to train on
DATA_FILE = "Monday-WorkingHours.pcap_ISCX.csv"

# Output filenames for our new "Version 2" model
MODEL_NAME = "model_v2.joblib"
SCALER_NAME = "scaler_v2.joblib"
ENCODERS_NAME = "encoders_v2.joblib"
COLUMNS_NAME = "model_columns_v2.joblib"
PROFILE_NAME = "normal_profile_v2.joblib" # For our Explainable AI (XAI) feature

# --- List of columns to drop ---
# These columns are either text-based, IDs, or the label itself
COLUMNS_TO_DROP = [
    'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 
    'Destination Port', 'Timestamp', 'Label'
]

# -----------------------------------------------------------------
# --- Phase 1: Load Data ---
# -----------------------------------------------------------------
print(f"--- [1/6] Loading Data ({DATA_FILE}) ---")
if not os.path.exists(DATA_FILE):
    print(f"Error: Data file not found: {DATA_FILE}")
    print("Please download a CIC-IDS-2017 CSV file and place it in this folder.")
    exit()
    
try:
    # Use encoding 'latin1' to avoid errors
    df = pd.read_csv(DATA_FILE, encoding='latin1')
    print(f"Loaded {len(df)} initial rows.")
except Exception as e:
    print(f"Error loading CSV. Error: {e}")
    exit()

# -----------------------------------------------------------------
# --- Phase 2: Clean Data ---
# -----------------------------------------------------------------
print("--- [2/6] Cleaning Data (Handling Inf, NaN, and Column Names) ---")

# --- THIS IS THE BUG FIX ---
# Strip all whitespace from column names (e.g., ' Source IP' -> 'Source IP')
df.columns = [col.strip() for col in df.columns]
# --- END OF BUG FIX ---

# Replace 'infinity' values with NaN (Not a Number)
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Drop all rows that have any NaN (missing) values
df.dropna(inplace=True)

print(f"Remaining rows after cleaning: {len(df)}")

# -----------------------------------------------------------------
# --- Phase 3: Preprocess & Encode ---
# -----------------------------------------------------------------
print("--- [3/6] Preprocessing and Encoding Labels ---")
encoders = {}
if 'Label' in df.columns:
    le = LabelEncoder()
    # Fit the encoder on the *entire* 'Label' column
    df['Label'] = le.fit_transform(df['Label'])
    encoders['Label'] = le
    print("Encoded 'Label' column.")
else:
    print("Error: 'Label' column not found.")
    exit()
    
# -----------------------------------------------------------------
# --- Phase 4: Filter for "BENIGN" (Normal) Traffic ---
# -----------------------------------------------------------------
print("--- [4/6] Filtering for 'BENIGN' (Normal) Traffic ---")

try:
    # Find the numeric code that 'LabelEncoder' assigned to 'BENIGN'
    benign_label_code = encoders['Label'].transform(['BENIGN'])[0]
except ValueError:
    print("Error: 'BENIGN' label not found. Found labels:", le.classes_)
    exit()

# Create our 'normal' dataset for training
df_normal = df[df['Label'] == benign_label_code].copy()

print(f"Found {len(df_normal)} 'BENIGN' samples to train on.")

# -----------------------------------------------------------------
# --- Phase 5: Create Final Training Dataset & XAI Profile ---
# -----------------------------------------------------------------
print("--- [5/6] Creating Final Feature Set & XAI Profile ---")

# --- THIS IS THE SECOND BUG FIX ---
# We make a "safe" list of columns to drop, just in case
# one doesn't exist in the dataframe for some reason.
cols_to_drop_existing = [col for col in COLUMNS_TO_DROP if col in df_normal.columns]
df_normal_features = df_normal.drop(columns=cols_to_drop_existing)
# --- END OF BUG FIX ---

# --- XAI FEATURE ---
# Save the average "normal" profile for later comparison
print("   ...Calculating average 'normal' profile for XAI...")
normal_profile = df_normal_features.mean()

# -----------------------------------------------------------------
# --- Phase 6: Train the AI Model & Save Assets ---
# -----------------------------------------------------------------
print("--- [6/6] Scaling, Training, and Saving All 'v2' Assets ---")

# 1. Scale all the numeric data
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df_normal_features)

# 2. Train the Isolation Forest
print("   ...Training Isolation Forest. This may take a few minutes...")
model = IsolationForest(contamination=0.05, random_state=42, n_jobs=-1)
model.fit(df_scaled)
print("   ...Model training complete.")

# 3. Save Everything
joblib.dump(model, MODEL_NAME)
joblib.dump(scaler, SCALER_NAME)
joblib.dump(encoders, ENCODERS_NAME)
joblib.dump(df_normal_features.columns, COLUMNS_NAME) # Save the final feature list
joblib.dump(normal_profile, PROFILE_NAME) # Save the XAI profile

print("--- All Done! New 'v2' assets are trained and saved. ---")