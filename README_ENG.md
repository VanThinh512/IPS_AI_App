# 🛡️ Multi-layered AI-integrated IPS System (Hybrid AI-IPS)

This is a Hybrid Intrusion Prevention System (IPS) project that combines Machine Learning models with network behavior monitoring rules (Heuristic & Stateful Inspection). The system is capable of automatically detecting, tracking, and blocking Brute Force, DoS/DDoS, and Botnet attacks in real-time.

## ✨ 4-Layer Defense Architecture (Defense in Depth)

The system is designed with a defense-in-depth mindset, protecting the server through 4 layers:

* **Layer 1 - Heuristic Engine (Anti-DoS):** Counts packet frequency (Packet Rate). Automatically blocks IPs with abnormal spam traffic (> 400 packets/2 seconds).
* **Layer 2 - Log Analysis (Log Monitor):** Monitors the `/var/log/auth.log` file in real-time to immediately block stealthy SSH Brute Force attacks (Low & Slow).
* **Layer 3 - AI Ensemble Model (Anti-Polymorphic Brute Force):** Machine Learning model predicts the suspicion score based on 21 network features (Flow duration, IAT, Length, etc.). The model achieves an accuracy of **99.96%**.
* **Layer 4 - Stateful TCP Limiting (Leaky Bucket Algorithm):** Monitors TCP flags (RST, FIN) to penalize fast scanning tools. Combines with the **Leaky Bucket** algorithm (risk dissipation) to deduct points from legitimate network flows, **ensuring 0% False Positives (No incorrect blocks)**.

---

## 📂 Project Folder Structure

* `ips_core.py`: The heart of the HIPS system, monitoring and blocking IPs in real-time.
* `models/`: Contains the pre-trained AI model (`ids_model.pkl`) and data scaler (`ids_scaler.pkl`).
* `training_model/`: Contains notebooks and data preprocessing results. Specifically, the `training_ensemble_model.ipynb` file is the source code for training the Ensemble model that achieved 99.96% accuracy.
* `attack/`: Contains attack simulation scripts like `botnet_attack.sh` and `test_medium.txt` (password dictionary) used for the Kali Linux machine.

---

## 🐧 Environment and Machine Setup:
- **Kali Machine:** Attacker machine - IP `192.168.73.134`
- **Ubuntu Machine:** Target machine integrating the AI-IPS system - IP `192.168.73.137`
- **Operating System:** Linux
- **Environment:** VMware Workstation
- **Network:** NAT

## 🐧 Installation & Execution Guide on Ubuntu (Defender Machine)

### 1. Clone the repository and set up the environment

Open a terminal on Ubuntu and run the following commands sequentially:

```bash
git clone https://github.com/VanThinh512/IPS_AI_App.git
cd AI_IPS_Project

# Create and activate the virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 2. Launch the IPS System (Requires opening 3 Terminals)

To observe comprehensively, open 3 separate Terminal windows on Ubuntu:

* **Terminal 1 (Flush Firewall):**
    ```bash
    sudo iptables -F
    ```
* **Terminal 2 (Start IPS):**
    ```bash
    source venv/bin/activate
    sudo ./venv/bin/python ips_core.py
    ```
* **Terminal 3 (Real-time Firewall Monitoring):**
    Used to verify if the system has added the attacker's IP to the blocklist (DROP):
    ```bash
    sudo iptables -L -n
    ```

> **⚠️ Note:** `sudo` privileges are required for the IPS to sniff packets at Layer 3 and execute `iptables` commands.

---

## 🐉 Attack Guide on Kali Linux (Attacker Machine)

### 1. Prepare Attack Scenarios

Copy the `attack` folder from the project to your Kali Linux machine. Grant execution permissions for the scripts:

```bash
chmod +x attack/botnet_attack.sh
```

### 2. System Testing Demo Scenarios

* **Scenario 1: Botnet Magic Routing (Bypassing Firewall):**
    This script simulates a Botnet network, continuously changing IPs (`.134`, `.135`, `.136`) and performing Brute Force attacks using Hydra.
    ```bash
    sudo ./attack/botnet_attack.sh
    ```
    *-> Expected result: IPS tracks and blocks each spoofed IP independently.*

* **Scenario 2: Denial of Service Attack (TCP SYN Flood):**
    ```bash
    sudo hping3 -S -p 21 --flood <IP_Ubuntu>
    ```
    *-> Expected result: The Heuristic layer blocks the IP immediately within 1 second.*

* **Scenario 3: Violent Password Scanning (Brute Force):**
    Attack using Ncrack to create fast TCP connection teardown behaviors.
    ```bash
    ncrack -u admin -P attack/test_medium.txt ssh://<IP_Ubuntu>
    ```
    *-> Expected result: The AI layer and TCP State mechanism coordinate to accumulate risk scores and block the IP.*
