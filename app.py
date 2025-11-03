import streamlit as st
import pandas as pd
import joblib
import time
import numpy as np
import socket
from datetime import datetime
import threading
import os
import geoip2.database # <-- Need this
import altair as alt    # <-- Need this

# -----------------------------------------------------------------
# App Configuration
# -----------------------------------------------------------------
LOG_FILE = "honeypot_alerts.log"
HONEYPOT_PORT = 2222
GEOIP_DB = "GeoLite2-Country.mmdb"

st.set_page_config(
    page_title="AI-Driven Security Suite v2",
    page_icon="🚀",
    layout="wide"
)

# --- (Section 1: Honeypot Background Thread) ---
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
                    try:
                        conn.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\n")
                    except socket.error:
                        pass
    except OSError as e:
        if e.errno == 98:
             print(f"--- [Honeypot Thread Warning]: Port {HONEYPOT_PORT} already in use. ---")
        else:
             print(f"--- [Honeypot Thread Error]: {e} ---")
    except Exception as e:
        print(f"--- [Honeypot Thread Error]: {e} ---")

# --- (End of Section 1) ---

# --- (Section 2: AI Model & Data Loading) ---
@st.cache_resource
def load_assets():
    assets = {}
    try:
        assets["model"] = joblib.load("ids_model.joblib")
        assets["scaler"] = joblib.load("ids_scaler.joblib")
        assets["encoders"] = joblib.load("ids_encoders.joblib")
        assets["geoip_reader"] = geoip2.database.Reader(GEOIP_DB)
    except FileNotFoundError as e:
        st.error(f"Required file not found! {e}. Run train.py and ensure GeoLite2-Country.mmdb exists.", icon="🚨")
        return None
    except Exception as e:
        st.error(f"Error loading assets: {e}", icon="🚨")
        return None
    return assets

@st.cache_data
def load_test_data(_assets):
    col_names = ["duration","protocol_type","service","flag","src_bytes",
        "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
        "logged_in","num_compromised","root_shell","su_attempted","num_root",
        "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
        "is_host_login","is_guest_login","count","srv_count","serror_rate",
        "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
        "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
        "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
        "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]
    try:
        df_test = pd.read_csv("KDDTest+.txt", header=None, names=col_names)
    except FileNotFoundError:
        st.error("KDDTest+.txt not found!", icon="🚨")
        return None, None, None

    true_labels = df_test['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')
    df_test_clean = df_test.drop(columns=['label', 'difficulty'])
    
    categorical_cols = ['protocol_type', 'service', 'flag']
    df_test_processed = df_test_clean.copy()

    encoders = _assets.get("encoders") # Use .get for safety
    scaler = _assets.get("scaler")

    if not encoders or not scaler:
         st.error("Scaler or Encoders not loaded correctly from assets.", icon="🚨")
         return None, None, None

    for col in categorical_cols:
        if col in encoders:
             le = encoders[col]
             df_test_processed[col] = df_test_processed[col].apply(lambda x: le.transform([x])[0] if x in le.classes_ else -1)
        else:
            st.warning(f"Encoder for column '{col}' not found. Skipping encoding for this column.")


    df_test_scaled = scaler.transform(df_test_processed)
    
    return df_test_clean, df_test_scaled, true_labels

# --- (End of Section 2) ---

# --- (Section 3: App State & Helper Functions) ---
KNOWN_BAD_IPS = {"1.1.1.1", "8.8.8.8", "123.123.123.123"}

def block_ip(ip_to_block):
    st.session_state.blocked_ips.add(ip_to_block)
    if ip_to_block in st.session_state.pending_alerts:
        del st.session_state.pending_alerts[ip_to_block]
    if ip_to_block in st.session_state.honeypot_alerts:
        del st.session_state.honeypot_alerts[ip_to_block]

def get_country(ip, reader):
    if not reader: return "N/A"
    try:
        response = reader.country(ip)
        # Handle cases where country name might be None
        return response.country.name if response.country and response.country.name else "Unknown"
    except geoip2.errors.AddressNotFoundError:
        return "Local/Private" # More specific than Unknown
    except Exception as e:
        print(f"GeoIP Error for {ip}: {e}") # Log the error
        return "Error"

# Initialize Session State
if 'simulation_running' not in st.session_state: st.session_state.simulation_running = False
if 'current_index' not in st.session_state: st.session_state.current_index = 0
if 'metrics' not in st.session_state: st.session_state.metrics = {"total": 0, "anomalies": 0, "normal": 0}
if 'pending_alerts' not in st.session_state: st.session_state.pending_alerts = {}
if 'blocked_ips' not in st.session_state: st.session_state.blocked_ips = set()
if 'honeypot_alerts' not in st.session_state: st.session_state.honeypot_alerts = {}
if 'service_counts' not in st.session_state: st.session_state.service_counts = {}

# --- (End of Section 3) ---

# -----------------------------------------------------------------
# --- MAIN APP EXECUTION ---
# -----------------------------------------------------------------

# 1. Load Assets
assets = load_assets()
if not assets:
    st.stop()
else:
    # Unpack assets here IF they loaded successfully
    model = assets.get("model")
    scaler = assets.get("scaler")
    encoders = assets.get("encoders")
    geoip_reader = assets.get("geoip_reader")


# 2. Load Data (only if assets loaded)
if model and scaler and encoders: # Check if essential assets are loaded
    df_test_raw, test_data_scaled, true_labels = load_test_data(assets)
    if df_test_raw is None:
        st.stop()
else:
    st.error("Essential AI assets (model/scaler/encoders) failed to load.", icon="🛑")
    st.stop()


# 3. Start Honeypot Thread
if 'honeypot_thread_started' not in st.session_state:
    print("--- [Streamlit App]: First run, starting honeypot thread. ---")
    if os.path.exists(LOG_FILE):
        try:
            os.remove(LOG_FILE)
        except OSError as e:
            print(f"Warning: Could not remove old log file {LOG_FILE}: {e}")

    thread = threading.Thread(target=start_honeypot, daemon=True)
    thread.start()
    st.session_state.honeypot_thread_started = True

# --- **THIS IS THE CRUCIAL SECTION TO CHECK** ---
# 4. Update Honeypot Alerts from Log File
latest_honeypot_ips = set()
try:
    if os.path.exists(LOG_FILE):
        # Important: Ensure file is not empty before reading
        if os.path.getsize(LOG_FILE) > 0:
            df_hp_alerts = pd.read_csv(LOG_FILE, header=None, names=["Timestamp", "IP"])
            if not df_hp_alerts.empty:
                latest_alerts = df_hp_alerts.loc[df_hp_alerts.groupby('IP')['Timestamp'].idxmax()]
                
                for index, row in latest_alerts.iterrows():
                    ip = row['IP']
                    timestamp = row['Timestamp']
                    latest_honeypot_ips.add(ip)
                    
                    if ip not in st.session_state.blocked_ips and ip not in st.session_state.honeypot_alerts:
                        st.session_state.honeypot_alerts[ip] = timestamp
                        print(f"DEBUG: Added honeypot alert for {ip}") # Debug print
except pd.errors.EmptyDataError:
    print(f"DEBUG: Honeypot log file '{LOG_FILE}' is empty.") # Okay if file is just created
except Exception as e:
    print(f"Error reading honeypot log: {e}")

# Cleanup stale/blocked alerts
ips_to_remove = [ip for ip in st.session_state.honeypot_alerts if ip not in latest_honeypot_ips or ip in st.session_state.blocked_ips]
for ip in ips_to_remove:
    del st.session_state.honeypot_alerts[ip]
    print(f"DEBUG: Removed stale/blocked honeypot alert for {ip}")
# --- **END OF CRUCIAL SECTION** ---


# -----------------------------------------------------------------
# --- (Section 4: Streamlit UI Dashboard) ---
# -----------------------------------------------------------------

st.title("🛡️ AI Security Suite Dashboard v2 🚀")
st.caption(f"Honeypot active on port {HONEYPOT_PORT}. AI Engine ready for {len(test_data_scaled)} packets.")

# --- Part A: Active Threat Panel ---
st.header("⚠️ Active Threats Requiring Action")
threat_col1, threat_col2 = st.columns(2)

with threat_col1:
    st.subheader("🍯 Honeypot 'Tripwire' Alerts")
    # --- ADD THE REFRESH BUTTON HERE ---
    if st.button("🔄 Refresh Honeypot Alerts"):
        print("DEBUG: Refresh button clicked.") # Debug print
        # Clearing and re-reading logic is now handled above, just need to rerun
        st.rerun()
    # --- END REFRESH BUTTON ---
    hp_alert_placeholder = st.container(height=300)
    with hp_alert_placeholder:
        if not st.session_state.honeypot_alerts: st.info("No new attackers via honeypot.")
        
        for ip, timestamp in list(st.session_state.honeypot_alerts.items()):
            country = get_country(ip, geoip_reader) # Use the loaded reader
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
            st.warning(f"**IP:** `{ip}` ({country}) | **Svc:** `{info['service']}` | **True:** `{info['true_label']}`")
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
        st.session_state.service_counts = {}
        st.rerun()

    m_col1, m_col2, m_col3 = st.columns(3)
    m_col1.metric("Packets Analyzed", st.session_state.metrics["total"])
    m_col2.metric("Anomalies Found", st.session_state.metrics["anomalies"])
    m_col3.metric("Normal Found", st.session_state.metrics["normal"])

    st.caption("Live AI Anomaly Scan Feed (from KDDTest+.txt)")
    live_feed_placeholder = st.container(height=300)

with sim_col2:
    st.subheader("🚫 Blocklist")
    blocked_placeholder = st.container(height=450)
    with blocked_placeholder:
        if not st.session_state.blocked_ips: st.info("No IPs blocked.")
        for ip in sorted(list(st.session_state.blocked_ips)):
            country = get_country(ip, geoip_reader)
            st.code(f"{ip} ({country})", language="text")

st.divider()

# --- Part C: Visualizations Panel ---
st.header("📊 Data Visualizations")
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("Anomaly vs Normal")
    pie_data = pd.DataFrame({
        'category': ['Anomalies', 'Normal'],
        'count': [st.session_state.metrics['anomalies'], st.session_state.metrics['normal']]
    })
    
    chart = alt.Chart(pie_data).mark_arc(outerRadius=120).encode(
        theta=alt.Theta(field="count", type="quantitative", stack=True), # Added stack=True
        color=alt.Color(field="category", type="nominal",
                       scale=alt.Scale(domain=['Anomalies', 'Normal'], range=['#e45756', '#54a24b'])), # Specific colors
        order=alt.Order(field="count", sort="descending"), # Order slices
        tooltip=['category', 'count']
    ).properties(
        title='AI Detection Results'
    )
    if st.session_state.metrics['total'] > 0:
        st.altair_chart(chart, use_container_width=True)
    else:
        st.caption("Run AI Scan to see results.")

with chart_col2:
    st.subheader("Top Attacked Services (Anomalies)")
    if st.session_state.service_counts:
        service_data = pd.DataFrame(list(st.session_state.service_counts.items()), columns=['Service', 'Count'])
        service_data = service_data.sort_values(by='Count', ascending=False).head(10)
        
        bar_chart = alt.Chart(service_data).mark_bar().encode(
            x=alt.X('Count', type='quantitative', title='Number of Alerts'),
            y=alt.Y('Service', type='nominal', sort='-x', title='Service Name'),
            tooltip=['Service', 'Count']
        ).properties(
            title='Top 10 Services Targeted in Anomalies'
        )
        st.altair_chart(bar_chart, use_container_width=True)
    else:
        st.caption("Run AI Scan to see results.")

# --- (End of Section 4) ---

# -----------------------------------------------------------------
# --- (Section 5: Simulation Loop) ---
# -----------------------------------------------------------------
if st.session_state.simulation_running:
    i = st.session_state.current_index
    if i < len(test_data_scaled):
        packet_data_scaled = test_data_scaled[i:i+1]
        packet_data_raw = df_test_raw.iloc[i]
        true_label = true_labels.iloc[i]
        
        # Check if model object exists before predicting
        if model:
            prediction = model.predict(packet_data_scaled)
            is_anomaly = (prediction[0] == -1)
        else:
            st.error("Model object not found during simulation.", icon="🛑")
            st.session_state.simulation_running = False # Stop simulation
            is_anomaly = False # Avoid further errors
            st.rerun()


        mock_ip = f"192.168.{packet_data_raw['duration'] % 255}.{packet_data_raw['src_bytes'] % 255}"
        service = packet_data_raw['service']
        
        st.session_state.metrics["total"] += 1
        
        with live_feed_placeholder:
            if is_anomaly:
                st.session_state.metrics["anomalies"] += 1
                st.warning(f"**Anomaly!** (True: {true_label}) | IP: {mock_ip} | Svc: {service}")
                st.session_state.service_counts[service] = st.session_state.service_counts.get(service, 0) + 1
                
                if mock_ip not in st.session_state.pending_alerts and mock_ip not in st.session_state.blocked_ips:
                    st.session_state.pending_alerts[mock_ip] = { "service": service, "true_label": true_label }
            else:
                st.session_state.metrics["normal"] += 1
                st.success(f"**OK** (True: {true_label}) | IP: {mock_ip} | Svc: {service}")
        
        st.session_state.current_index += 1
        time.sleep(0.01) # Faster simulation
        st.rerun()

    else:
        st.session_state.simulation_running = False
        st.balloons()
        st.success("AI Simulation Complete!")
        st.rerun()

# --- (End of Section 5) ---