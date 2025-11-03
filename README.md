# AI-Driven Security Suite Dashboard 🛡️🚀

This project is a functional prototype of a unified cybersecurity dashboard, integrating a live multi-threaded honeypot with an AI-driven anomaly detection engine (IDS) to provide a single pane of glass for threat monitoring.

This was built for the **[TODO: Add Hackathon Name Here]**.

---

### ✨ Live Dashboard Preview

**[TODO: Insert a GIF or screenshot of your dashboard in action here!]**

*(To get a screenshot URL: take a screenshot, go to your GitHub repo, click the "Issues" tab, make a "New Issue," drag-and-drop your image into the text box, and copy the URL it generates. You can then close the issue without saving and paste the URL here.)*

---

## ## 🎯 Core Features

* **Real-Time Honeypot:** Includes a simple, multi-threaded SSH honeypot (running on port `2222`) that logs all connection attempts instantly without blocking the main application.
* **Modern AI Anomaly Detection (IDS):** Uses a **Scikit-learn Isolation Forest** model trained on the modern **CIC-IDS-2017** dataset to detect complex, modern attack patterns like DDoS, Brute Force, and Web Attacks.
* **Explainable AI (XAI):** Features a "Why was this flagged?" explainer that compares anomalous packets to the baseline "Normal" profile and highlights the top 3 most suspicious features.
* **Integrated Threat Intelligence:**
    * **GeoIP Lookup:** Automatically enriches all alerts (from both honeypot and AI) with the attacker's country of origin using the MaxMind GeoLite2 database.
    * **Signature Matching:** Checks honeypot attackers against a basic "known bad IP" list for high-priority alerts.
* **Simulated IPS (Intrusion Prevention):** A unified dashboard where an analyst can review all alerts from both systems and click "Block IP" to add the threat actor to a master blocklist.
* **Data Visualization:** Uses **Altair** to generate real-time charts for the AI engine, showing:
    * A pie chart of the "Normal vs. Anomaly" breakdown.
    * A bar chart of the "Top Detected Attack Types" (e.g., `DDoS`, `SSH-Patator`).

---

## ## 🏛️ Project Architecture

This application runs as a single Streamlit app (`app_v2.py`) but uses **multi-threading** to operate two systems simultaneously:

1.  **Honeypot Thread:** A background thread (`socket`) opens port `2222` and listens for any incoming TCP connections. When a connection is detected, it logs the attacker's IP to `honeypot_alerts.log`, sends a fake SSH banner, and disconnects the user.
2.  **Main Streamlit Thread:** The main thread runs the interactive web dashboard. On every page refresh (e.g., when a button is clicked or the AI simulation runs), it:
    * Re-reads the `honeypot_alerts.log` file to display new external alerts.
    * If the "Start AI Scan" button is pressed, it processes one line from the `Tuesday-WorkingHours.csv` test file.
    * It cleans the data, feeds it to the trained `model_v2.joblib`, and gets a prediction (Normal or Anomaly).
    * It updates all UI components (charts, alert lists, blocklist) based on the current state.

---

## ## 🛠️ Tech Stack

* **Language:** Python
* **AI / Data Science:** Scikit-learn, Pandas, NumPy
* **Dashboard:** Streamlit
* **Visualization:** Altair
* **Threat Intel:** GeoIP2
* **Core Libraries:** Socket, Threading, Joblib

---

## ## ⚙️ Setup and Installation

This project uses `.gitignore` to exclude large data files, models, and environment files. You must download these dependencies manually.

### Step 1: Clone the Repository
```bash
git clone [https://github.com/](https://github.com/)IOTJr/-ai-ids-.git
cd -ai-ids-


STEP 2

# Create a virtual environment
python -m venv venv

# Activate it (Windows)
.\venv\Scripts\activate

# Activate it (macOS/Linux)
# source venv/bin/activate

# Install all required libraries
pip install -r requirements.txt


Here is a full, professional README.md file for your GitHub project.

## How to Use This
In your ai-ids-project folder in VS Code, create a new file named exactly README.md.

Copy and paste all the text from the code block below into that new file.

Crucially: Find the two [TODO: ...] placeholders and replace them with your own information.

Save the file, then git add README.md, git commit -m "Add project README", and git push.

Your GitHub repository will now have this as its front page.

Markdown

# AI-Driven Security Suite Dashboard 🛡️🚀

This project is a functional prototype of a unified cybersecurity dashboard, integrating a live multi-threaded honeypot with an AI-driven anomaly detection engine (IDS) to provide a single pane of glass for threat monitoring.

This was built for the **[TODO: Add Hackathon Name Here]**.

---

### ✨ Live Dashboard Preview

**[TODO: Insert a GIF or screenshot of your dashboard in action here!]**

*(To get a screenshot URL: take a screenshot, go to your GitHub repo, click the "Issues" tab, make a "New Issue," drag-and-drop your image into the text box, and copy the URL it generates. You can then close the issue without saving and paste the URL here.)*

---

## ## 🎯 Core Features

* **Real-Time Honeypot:** Includes a simple, multi-threaded SSH honeypot (running on port `2222`) that logs all connection attempts instantly without blocking the main application.
* **Modern AI Anomaly Detection (IDS):** Uses a **Scikit-learn Isolation Forest** model trained on the modern **CIC-IDS-2017** dataset to detect complex, modern attack patterns like DDoS, Brute Force, and Web Attacks.
* **Explainable AI (XAI):** Features a "Why was this flagged?" explainer that compares anomalous packets to the baseline "Normal" profile and highlights the top 3 most suspicious features.
* **Integrated Threat Intelligence:**
    * **GeoIP Lookup:** Automatically enriches all alerts (from both honeypot and AI) with the attacker's country of origin using the MaxMind GeoLite2 database.
    * **Signature Matching:** Checks honeypot attackers against a basic "known bad IP" list for high-priority alerts.
* **Simulated IPS (Intrusion Prevention):** A unified dashboard where an analyst can review all alerts from both systems and click "Block IP" to add the threat actor to a master blocklist.
* **Data Visualization:** Uses **Altair** to generate real-time charts for the AI engine, showing:
    * A pie chart of the "Normal vs. Anomaly" breakdown.
    * A bar chart of the "Top Detected Attack Types" (e.g., `DDoS`, `SSH-Patator`).

---

## ## 🏛️ Project Architecture

This application runs as a single Streamlit app (`app_v2.py`) but uses **multi-threading** to operate two systems simultaneously:

1.  **Honeypot Thread:** A background thread (`socket`) opens port `2222` and listens for any incoming TCP connections. When a connection is detected, it logs the attacker's IP to `honeypot_alerts.log`, sends a fake SSH banner, and disconnects the user.
2.  **Main Streamlit Thread:** The main thread runs the interactive web dashboard. On every page refresh (e.g., when a button is clicked or the AI simulation runs), it:
    * Re-reads the `honeypot_alerts.log` file to display new external alerts.
    * If the "Start AI Scan" button is pressed, it processes one line from the `Tuesday-WorkingHours.csv` test file.
    * It cleans the data, feeds it to the trained `model_v2.joblib`, and gets a prediction (Normal or Anomaly).
    * It updates all UI components (charts, alert lists, blocklist) based on the current state.

---

## ## 🛠️ Tech Stack

* **Language:** Python
* **AI / Data Science:** Scikit-learn, Pandas, NumPy
* **Dashboard:** Streamlit
* **Visualization:** Altair
* **Threat Intel:** GeoIP2
* **Core Libraries:** Socket, Threading, Joblib

---

## ## ⚙️ Setup and Installation

This project uses `.gitignore` to exclude large data files, models, and environment files. You must download these dependencies manually.

### Step 1: Clone the Repository
```bash
git clone [https://github.com/](https://github.com/)[YOUR-USERNAME]/[YOUR-REPO-NAME].git
cd [YOUR-REPO-NAME]
Step 2: Create Environment & Install Requirements
Bash

# Create a virtual environment
python -m venv venv

# Activate it (Windows)
.\venv\Scripts\activate

# Activate it (macOS/Linux)
# source venv/bin/activate

# Install all required libraries
pip install -r requirements.txt
Step 3: Download External Dependencies (CRITICAL)
You must download these files and place them in the project's root folder:

Datasets (CIC-IDS-2017):

Download: Get the CSV files from the CIC-IDS-2017 Dataset page.

Training File: You need the file specified in train.py (e.g., Monday-WorkingHours.pcap_ISCX.csv).

Testing File: You need the file specified in app_v2.py (e.g., Tuesday-WorkingHours.pcap_ISCX.csv).

GeoIP Database:

Download: Get the free GeoLite2-Country.mmdb database from MaxMind.

Place: Put the GeoLite2-Country.mmdb file in the same folder as app_v2.py.

## 🚀 How to Run the Demo
Step 1: Train the AI Model
First, you must run the train.py script to create your _v2.joblib model files from the training data.

Bash

python train.py
(This may take a few minutes as it processes the large CSV file)

Step 2: Run the Security Suite Dashboard
Once training is complete, run the main app_v2.py file.

Bash

streamlit run app_v2.py
Your browser will automatically open to the dashboard.

Step 3: Test the System!
Test the Honeypot:

Find your computer's local IP (e.g., 192.168.1.10) by running ipconfig (Windows) or ifconfig (Mac/Linux).

From another machine (like your Kali VM), "attack" the honeypot:

Bash

telnet 192.168.1.10 2222
Watch the "Honeypot 'Tripwire' Alerts" panel on the dashboard. Your Kali VM's IP will appear. Click the Block button to add it to the Master Blocklist.

Test the AI Engine:

On the dashboard, click the "▶️ Start/Resume AI Scan" button.

Watch the "Live AI Anomaly Scan Feed" as it processes packets from the test file.

When an anomaly is detected, it will appear in the "AI Anomaly Alerts" panel and the charts at the bottom will update.

Click the "Why was this flagged?" expander to see the XAI explanation for an alert.

## 💡 Future Improvements
This is a prototype with a clear path for expansion:

Real-Time Packet Sniffing: Replace the CSV-based "simulation" with a real packet sniffer using Zeek or Scapy, which would feed data into a Kafka stream for the AI to analyze.

Automated IPS: Integrate with a real firewall (like pfSense or Fortinet) API to make the "Block IP" button automatically update a real network rule.

Advanced XAI: Implement more advanced XAI libraries like SHAP or LIME to generate more robust feature-importance graphs.
