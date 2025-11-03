import streamlit as st
import pandas as pd
import joblib
import time
import numpy as np
import socket
from datetime import datetime
import threading
import os
import geoip2.database
import altair as alt

# -----------------------------------------------------------------
# --- Configuration ---
# -----------------------------------------------------------------
LOG_FILE = "honeypot_alerts.log"
HONEYPOT_PORT = 2222
GEOIP_DB = "GeoLite2-Country.mmdb"
KNOWN_BAD_IPS = {"1.1.1.1", "8.8.8.8", "123.123.123.123"}

# --- v2 Model Configuration ---
MODEL_NAME = "model_v2.joblib"
SCALER_NAME = "scaler_v2.joblib"
ENCODERS_NAME = "encoders_v2.joblib"
COLUMNS_NAME = "model_columns_v2.joblib"
PROFILE_NAME = "normal_profile_v2.joblib"

# --- NEW: Test Data File ---
# Change this to the *other* file you downloaded for testing
TEST_DATA_FILE = "Tuesday-WorkingHours.pcap_ISCX.csv"

# --- NEW: Columns to drop before prediction ---
# These are text/meta columns that the model wasn't trained on
COLUMNS_TO_DROP = [
    'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 
    'Destination Port', 'Timestamp', 'Label'
]


st.set_page_config(
    page_title="AI-Driven Security Suite v2 (CIC-IDS-2017)",
    page_icon="🚀",
    layout="wide"
)

# -----------------------------------------------------------------
# --- (Section 1: Honeypot Background Thread) ---
# -----------------------------------------------------------------
def log_honeypot_attempt(ip):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"{timestamp},{ip}\n"
    print(f"HONEYPOT HIT! IP: {ip}, logged to {LOG_FILE}")
    with open(LOG_FILE, "a") as f:
        f.write(log_message)

def start_honeypot():
    HOST = '0.0.0.0'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, HONEYPOT_PORT))
            s.listen()
            print(f"--- [Honeypot Thread]: Listening on port {HONEYPOT_PORT} ---")
            while True:
                conn, addr = s.accept()
                with conn:
                    ip = addr[0]
                    log_honeypot_attempt(ip)
                    try: conn.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\n")
                    except socket.error: pass
    except OSError as e:
        if e.errno == 98 or e.errno == 10048: # Address already in use
             print(f"--- [Honeypot Thread Warning]: Port {HONEYPOT_PORT} already in use. ---")
        else: print(f"--- [Honeypot Thread Error]: {e} ---")
    except Exception as e:
        print(f"--- [Honeypot Thread Error]: {e} ---")
# --- (End of Section 1) ---


# -----------------------------------------------------------------
# --- (Section 2: AI Model & Data Loading) ---
# -----------------------------------------------------------------
@st.cache_resource
def load_assets():
    """Loads all v2 assets: model, scaler, encoders, GeoIP, etc."""
    assets = {}
    all_files_found = True
    
    # List of files we absolutely need
    required_files = [
        MODEL_NAME, SCALER_NAME, ENCODERS_NAME, 
        COLUMNS_NAME, PROFILE_NAME, GEOIP_DB
    ]
    
    for f in required_files:
        if not os.path.exists(f):
            st.error(f"Missing required file: {f}. Please run train.py and download the GeoIP database.", icon="🚨")
            all_files_found = False

    if not all_files_found:
        return None

    try:
        assets["model"] = joblib.load(MODEL_NAME)
        assets["scaler"] = joblib.load(SCALER_NAME)
        assets["encoders"] = joblib.load(ENCODERS_NAME)
        assets["model_columns"] = joblib.load(COLUMNS_NAME)
        assets["normal_profile"] = joblib.load(PROFILE_NAME) # For XAI
        assets["geoip_reader"] = geoip2.database.Reader(GEOIP_DB)
    except Exception as e:
        st.error(f"Error loading assets: {e}", icon="🚨")
        return None
        
    print("--- [Streamlit App]: All v2 assets loaded successfully. ---")
    return assets

@st.cache_data
def load_test_data(_assets):
    """Loads and preprocesses the CIC-IDS-2017 TEST file."""
    try:
        df_test = pd.read_csv(TEST_DATA_FILE, encoding='latin1')
    except FileNotFoundError:
        st.error(f"Test data file not found: {TEST_DATA_FILE}. Please download it.", icon="🚨")
        return None, None, None
    except Exception as e:
        st.error(f"Error loading test CSV: {e}", icon="🚨")
        return None, None, None

    # --- Perform identical cleaning as train.py ---
    df_test.columns = [col.strip() for col in df_test.columns]
    df_test.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_test.dropna(inplace=True)

    if df_test.empty:
        st.error(f"Test data '{TEST_DATA_FILE}' is empty after cleaning. Cannot proceed.")
        return None, None, None

    # Store the raw data for display *before* we drop columns
    df_test_raw_display = df_test.copy()

    # Get the label encoder
    le = _assets["encoders"].get('Label')
    if not le:
        st.error("Label encoder not found in assets!")
        return None, None, None

    # Get text labels for display (e.g., 'BENIGN', 'DDoS')
    if 'Label' in df_test.columns:
        # Use a lambda to handle labels that were not in the training set
        df_test['Label_Code'] = df_test['Label'].apply(lambda x: le.transform([x])[0] if x in le.classes_ else -1)
        true_labels_text = df_test['Label']
    else:
        st.error("Test data is missing the 'Label' column.")
        return None, None, None

    # Prepare the feature set for the model
    # Drop all non-feature columns
    cols_to_drop_existing = [col for col in COLUMNS_TO_DROP if col in df_test.columns]
    df_test_features = df_test.drop(columns=cols_to_drop_existing)

    # --- CRITICAL: Ensure column order matches the model ---
    model_columns = _assets["model_columns"]
    # Reorder our test data to match the column order the model was trained on
    df_test_features = df_test_features[model_columns] 
    
    # Scale the data
    scaler = _assets["scaler"]
    df_test_scaled = scaler.fit_transform(df_test_features)
    
    print("--- [Streamlit App]: Test data loaded and preprocessed. ---")
    # Return raw data, scaled data, and the text labels
    return df_test_raw_display, df_test_scaled, true_labels_text

# --- (End of Section 2) ---


# -----------------------------------------------------------------
# --- (Section 3: App State & Helper Functions) ---
# -----------------------------------------------------------------
def block_ip(ip_to_block):
    """Adds an IP to the blocklist and removes it from pending alerts."""
    st.session_state.blocked_ips.add(ip_to_block)
    if ip_to_block in st.session_state.pending_alerts:
        del st.session_state.pending_alerts[ip_to_block]
    if ip_to_block in st.session_state.honeypot_alerts:
        del st.session_state.honeypot_alerts[ip_to_block]

def get_country(ip, reader):
    """Looks up the country of an IP address."""
    if not reader: return "N/A"
    try:
        response = reader.country(ip)
        return response.country.name if response.country and response.country.name else "Unknown"
    except geoip2.errors.AddressNotFoundError:
        return "Local/Private" # This is what you'll see for your Kali VM
    except Exception:
        return "N/A" # General catch-all

# Initialize Session State
if 'simulation_running' not in st.session_state: st.session_state.simulation_running = False
if 'current_index' not in st.session_state: st.session_state.current_index = 0
if 'metrics' not in st.session_state: st.session_state.metrics = {"total": 0, "anomalies": 0, "normal": 0}
if 'pending_alerts' not in st.session_state: st.session_state.pending_alerts = {}
if 'blocked_ips' not in st.session_state: st.session_state.blocked_ips = set()
if 'honeypot_alerts' not in st.session_state: st.session_state.honeypot_alerts = {}
if 'attack_counts' not in st.session_state: st.session_state.attack_counts = {} # For bar chart

# --- (End of Section 3) ---


# -----------------------------------------------------------------
# --- MAIN APP EXECUTION ---
# -----------------------------------------------------------------

# 1. Load Assets
assets = load_assets()
if not assets: 
    st.header("Project Assets Not Found!")
    st.warning("Could not load all required files (`.joblib`, `.mmdb`).")
    st.markdown("""
    Please ensure you have run `train.py` successfully.
    
    Also, make sure you have downloaded the `GeoLite2-Country.mmdb` file
    from MaxMind and placed it in the same folder as this app.
    """)
    st.stop() # Stop the app if assets failed to load
    
# Unpack assets for use
model = assets.get("model")
scaler = assets.get("scaler")
encoders = assets.get("encoders")
geoip_reader = assets.get("geoip_reader")
model_columns = assets.get("model_columns")
normal_profile = assets.get("normal_profile") # For XAI

# 2. Load Data
df_test_raw, test_data_scaled, true_labels = load_test_data(assets)
if df_test_raw is None: 
    st.stop() # Stop if data failed to load

# 3. Start Honeypot Thread
if 'honeypot_thread_started' not in st.session_state:
    print("--- [Streamlit App]: First run, starting honeypot thread. ---")
    if os.path.exists(LOG_FILE): 
        try: os.remove(LOG_FILE)
        except Exception as e: print(f"Could not clear log: {e}")
    thread = threading.Thread(target=start_honeypot, daemon=True)
    thread.start()
    st.session_state.honeypot_thread_started = True

# 4. Update Honeypot Alerts
# (This logic is identical to before)
latest_honeypot_ips = set()
try:
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
        df_hp_alerts = pd.read_csv(LOG_FILE, header=None, names=["Timestamp", "IP"])
        if not df_hp_alerts.empty:
            latest_alerts = df_hp_alerts.loc[df_hp_alerts.groupby('IP')['Timestamp'].idxmax()]
            for _, row in latest_alerts.iterrows():
                ip, timestamp = row['IP'], row['Timestamp']
                latest_honeypot_ips.add(ip)
                if ip not in st.session_state.blocked_ips and ip not in st.session_state.honeypot_alerts:
                    st.session_state.honeypot_alerts[ip] = timestamp
except pd.errors.EmptyDataError: pass
except Exception as e: print(f"Error reading honeypot log: {e}")

ips_to_remove = [ip for ip in st.session_state.honeypot_alerts if ip not in latest_honeypot_ips or ip in st.session_state.blocked_ips]
for ip in ips_to_remove: del st.session_state.honeypot_alerts[ip]

# -----------------------------------------------------------------
# --- (Section 4: Streamlit UI Dashboard) ---
# -----------------------------------------------------------------

st.title("🛡️ AI Security Suite v2 (CIC-IDS-2017 Model) 🚀")
st.caption(f"Honeypot active on port {HONEYPOT_PORT}. AI Engine ready to scan {len(test_data_scaled)} packets from {TEST_DATA_FILE}.")

# --- Part A: Active Threat Panel ---
st.header("⚠️ Active Threats Requiring Action")
threat_col1, threat_col2 = st.columns(2)

with threat_col1:
    st.subheader("🍯 Honeypot 'Tripwire' Alerts")
    if st.button("🔄 Refresh Honeypot Alerts"): st.rerun() 
    hp_alert_placeholder = st.container(height=300)
    with hp_alert_placeholder:
        if not st.session_state.honeypot_alerts: st.info("No new attackers via honeypot.")
        for ip, timestamp in list(st.session_state.honeypot_alerts.items()):
            country = get_country(ip, geoip_reader)
            is_known_bad = ip in KNOWN_BAD_IPS
            alert_prefix = "🚨 **KNOWN BAD IP!** 🚨" if is_known_bad else ""
            st.error(f"{alert_prefix} **IP:** `{ip}` ({country}) | **Time:** `{timestamp}`")
            st.button(f"Block {ip}", key=f"block_hp_{ip}", on_click=block_ip, args=(ip,))

with threat_col2:
    st.subheader("🤖 AI Anomaly Alerts")
    ai_alert_placeholder = st.container(height=300)
    with ai_alert_placeholder:
        if not st.session_state.pending_alerts: st.info("No new anomalies via AI engine.")
        for ip, info in list(st.session_state.pending_alerts.items()):
            country = get_country(ip, geoip_reader)
            st.warning(f"**IP:** `{ip}` ({country}) | **Port:** `{info['port']}` | **Attack:** `{info['true_label']}`")
            st.button(f"Block {ip}", key=f"block_ai_{ip}", on_click=block_ip, args=(ip,))

st.divider()

# --- Part B: Simulation & Blocklist Panel ---
st.header("🔬 AI Engine Monitor & IPS Control")
sim_col1, sim_col2 = st.columns([3, 1])

with sim_col1:
    st.subheader("AI Engine Controls & Feed")
    btn_col1, btn_col2, _ = st.columns([1, 1, 2])
    if btn_col1.button("▶️ Start/Resume AI Scan"):
        st.session_state.simulation_running = True
        st.rerun()
    if btn_col2.button("⏹️ Stop/Reset AI Scan"):
        st.session_state.simulation_running = False
        st.session_state.current_index = 0
        st.session_state.metrics = {"total": 0, "anomalies": 0, "normal": 0}
        st.session_state.pending_alerts = {}
        st.session_state.attack_counts = {}
        st.rerun()

    m_col1, m_col2, m_col3 = st.columns(3)
    m_col1.metric("Packets Analyzed", st.session_state.metrics["total"])
    m_col2.metric("Anomalies Found", st.session_state.metrics["anomalies"])
    m_col3.metric("Normal Found", st.session_state.metrics["normal"])

    st.caption(f"Live AI Anomaly Scan Feed (from {TEST_DATA_FILE})")
    live_feed_placeholder = st.container(height=300)

with sim_col2:
    st.subheader("🚫 Master Blocklist")
    blocked_placeholder = st.container(height=450)
    with blocked_placeholder:
        if not st.session_state.blocked_ips: st.info("No IPs blocked.")
        for ip in sorted(list(st.session_state.blocked_ips)):
            country = get_country(ip, geoip_reader)
            st.code(f"{ip} ({country})", icon="🚫")

st.divider()

# --- Part C: Visualizations Panel ---
st.header("📊 Data Visualizations (v2 Model)")
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("AI Detection Breakdown")
    pie_data = pd.DataFrame({
        'category': ['Anomalies', 'Normal'],
        'count': [st.session_state.metrics['anomalies'], st.session_state.metrics['normal']]
    })
    chart = alt.Chart(pie_data).mark_arc(outerRadius=120).encode(
        theta=alt.Theta(field="count", type="quantitative", stack=True),
        color=alt.Color(field="category", type="nominal",
                       scale=alt.Scale(domain=['Anomalies', 'Normal'], range=['#e45756', '#54a24b'])),
        order=alt.Order(field="count", sort="descending"),
        tooltip=['category', 'count']
    ).properties(title='AI Detection Results (Normal vs. Anomaly)')
    if st.session_state.metrics['total'] > 0:
        st.altair_chart(chart, use_container_width=True)
    else: st.caption("Run AI Scan to see results.")

with chart_col2:
    st.subheader("Top Detected Attack Types (from AI)")
    if st.session_state.attack_counts:
        attack_data = {k: v for k, v in st.session_state.attack_counts.items() if k != 'BENIGN'}
        if attack_data:
            attack_df = pd.DataFrame(list(attack_data.items()), columns=['Attack Type', 'Count'])
            attack_df = attack_df.sort_values(by='Count', ascending=False).head(10)
            
            bar_chart = alt.Chart(attack_df).mark_bar().encode(
                x=alt.X('Count', type='quantitative', title='Number of Alerts'),
                y=alt.Y('Attack Type', type='nominal', sort='-x'),
                color=alt.value('#e45756'),
                tooltip=['Attack Type', 'Count']
            ).properties(title='Top 10 Detected Attack Types')
            st.altair_chart(bar_chart, use_container_width=True)
        else:
            st.caption("Anomalies detected, but all were 'BENIGN' false positives.")
    else:
        st.caption("Run AI Scan to see attack type results.")

# --- (End of Section 4) ---


# -----------------------------------------------------------------
# --- (Section 5: Simulation Loop) ---
# -----------------------------------------------------------------
# This is the section where the IndentationError most likely occurred.
# All lines inside this first 'if' must be indented.
if st.session_state.simulation_running:
    
    i = st.session_state.current_index
    
    # This 'if' is indented once
    if i < len(test_data_scaled):
        
        # --- START OF BLOCK (Indented twice) ---
        # All lines here must be at the same level
        
        packet_data_scaled = test_data_scaled[i:i+1]
        packet_data_raw = df_test_raw.iloc[i]
        true_label = true_labels.iloc[i] 
        
        if model:
            prediction = model.predict(packet_data_scaled)
            is_anomaly = (prediction[0] == -1)
        else:
            st.error("Model object not found!", icon="🛑")
            st.session_state.simulation_running = False
            is_anomaly = False
            st.rerun()

        # These are the lines from the previous KeyError fix
        source_ip = packet_data_raw.get('Source IP', 'N/A')
        dest_port = packet_data_raw.get('Destination Port', 'N/A')
        
        # This line (where the error was) must be at the same level
        st.session_state.metrics["total"] += 1
        
        # This 'with' block must also be at the same level
        with live_feed_placeholder:
            if is_anomaly:
                st.session_state.metrics["anomalies"] += 1
                st.session_state.attack_counts[true_label] = st.session_state.attack_counts.get(true_label, 0) + 1
                st.warning(f"**Anomaly!** (True: {true_label}) | IP: {source_ip} | Port: {dest_port}")
                
                with st.expander("Why was this flagged? (AI Explanation)"):
                    try:
                        anomaly_features = packet_data_raw.filter(items=model_columns)
                        diff = (anomaly_features - normal_profile).abs().sort_values(ascending=False)
                        st.write("This packet's features were unusual compared to average 'BENIGN' traffic:")
                        for feature, value in diff.head(3).items():
                            st.markdown(f"- **{feature}**: `{anomaly_features[feature]:.2f}` (Normal: `{normal_profile[feature]:.2f}`)")
                    except Exception as e:
                        st.write(f"Error generating XAI: {e}")
                
                if source_ip not in st.session_state.pending_alerts and source_ip not in st.session_state.blocked_ips:
                    st.session_state.pending_alerts[source_ip] = { "port": dest_port, "true_label": true_label }
            
            else: # If it's normal
                st.session_state.metrics["normal"] += 1
                st.success(f"**OK** (True: {true_label}) | IP: {source_ip} | Port: {dest_port}")
        
        # These lines must also be at the same level
        st.session_state.current_index += 1
        time.sleep(0.01) # Faster simulation
        st.rerun()
        # --- END OF BLOCK (Indented twice) ---

    else:
        # This 'else' is indented once (matches the 'if i < ...')
        st.session_state.simulation_running = False
        st.balloons()
        st.success("AI Simulation Complete!")
        st.rerun()

# --- (End of Section 5) ---