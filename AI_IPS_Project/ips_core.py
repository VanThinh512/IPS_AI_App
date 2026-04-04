import sys
import os
import time
import joblib
import numpy as np
import pandas as pd
import threading
import re
from scapy.all import sniff, IP, TCP, UDP, get_if_addr
from collections import defaultdict
import subprocess
import warnings

warnings.filterwarnings("ignore")

# ==============================================================================
# 1. CẤU HÌNH HỆ THỐNG
# ==============================================================================
INTERFACE = "ens33" 
try:
    MY_IP = get_if_addr(INTERFACE)
    print(f"[INFO] Whitelist IP: {MY_IP}")
except:
    MY_IP = "127.0.0.1"

GATEWAY_IP = "192.168.73.1"
MIN_PACKETS_TO_PREDICT = 3 # Hạ xuống 3 để không bỏ lọt luồng cực ngắn
RISK_THRESHOLD = 0.5
BLOCKED_IPS = set()

try:
    print("[INIT] Đang tải mô hình AI...")
    model = joblib.load('models/ids_model.pkl')
    scaler = joblib.load('models/ids_scaler.pkl')
    print("[INIT] Tải mô hình thành công!")
except Exception as e:
    print(f"[ERROR] Lỗi load model: {e}")
    sys.exit(1)

FEATURE_COLS = [
    'flow duration', 'flow iat mean', 'flow iat std', 'flow iat max', 'flow iat min',
    'fwd iat mean', 'fwd iat std', 'total fwd packets', 'total backward packets',
    'fwd packet length mean', 'fwd packet length std', 'bwd packet length mean',
    'bwd packet length std', 'flow packets/s', 'flow bytes/s', 'fwd psh flags',
    'ack flag count', 'syn flag count', 'fin flag count', 'init_win_bytes_forward',
    'init_win_bytes_backward'
]

active_flows = {}
ip_risk_scores = defaultdict(float)
ip_packet_counts = defaultdict(int)
last_dos_reset_time = time.time()
last_decay_time = time.time()

# ==============================================================================
# 2. CẢI TIẾN 2: MODULE PHÂN TÍCH NHẬT KÝ (LOG ANALYSIS - CHỐNG SSH/WEB)
# ==============================================================================
def monitor_auth_log():
    log_path = "/var/log/auth.log"
    if not os.path.exists(log_path): return
    print(f"[MODULE] Log Monitor đang chạy: Giám sát {log_path}...")
    
    with open(log_path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            if "Failed password" in line:
                match = re.search(r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if match:
                    attacker_ip = match.group(1)
                    if attacker_ip == MY_IP or attacker_ip == GATEWAY_IP: continue
                    
                    ip_risk_scores[attacker_ip] += 0.25
                    print(f"\n[LOG_ALERT] Đăng nhập SSH sai từ {attacker_ip} | Risk: {ip_risk_scores[attacker_ip]:.2f}")
                    if ip_risk_scores[attacker_ip] >= RISK_THRESHOLD:
                        block_ip(attacker_ip, "Log-based Detection (SSH Brute Force)")

# ==============================================================================
# 3. CHỨC NĂNG CHẶN VÀ XỬ LÝ GÓI TIN
# ==============================================================================
def block_ip(ip_address, attack_type):
    if ip_address in BLOCKED_IPS: return
    print(f"\n[BLOCK] PHÁT HIỆN TẤN CÔNG: {attack_type}")
    print(f"        -> Thực thi chặn IP: {ip_address}")
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        BLOCKED_IPS.add(ip_address)
        print(f"[SUCCESS] Đã chặn IP: {ip_address}")
    except Exception as e:
        print(f"[FAIL] Lỗi iptables: {e}")

class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip, self.dst_ip = src_ip, dst_ip
        self.packets = []
        self.start_time = time.time()

    def add_packet(self, packet, direction):
        flags = {'FIN':0, 'SYN':0, 'PSH':0, 'ACK':0}
        if packet.haslayer(TCP):
            f = packet[TCP].flags
            if 'F' in f: flags['FIN'] = 1
            if 'S' in f: flags['SYN'] = 1
            if 'P' in f: flags['PSH'] = 1
            if 'A' in f: flags['ACK'] = 1
        
        self.packets.append({
            'time': time.time(),
            'size': len(packet),
            'direction': direction,
            'flags': flags,
            'win_size': packet[TCP].window if packet.haslayer(TCP) else 0
        })

    def extract_features(self):
        count = len(self.packets)
        if count == 0: return None
        dur = (self.packets[-1]['time'] - self.packets[0]['time']) * 1e6
        if dur == 0: dur = 1
        fwd = [p for p in self.packets if p['direction'] == 0]
        bwd = [p for p in self.packets if p['direction'] == 1]
        ts = [p['time'] * 1e6 for p in self.packets]
        iats = np.diff(ts) if len(ts) > 1 else [0]
        f_ts = [p['time'] * 1e6 for p in fwd]
        f_iats = np.diff(f_ts) if len(f_ts) > 1 else [0]
        
        feats = {
            'flow duration': dur, 'flow iat mean': np.mean(iats), 'flow iat std': np.std(iats),
            'flow iat max': np.max(iats), 'flow iat min': np.min(iats),
            'fwd iat mean': np.mean(f_iats), 'fwd iat std': np.std(f_iats),
            'total fwd packets': len(fwd), 'total backward packets': len(bwd),
            'fwd packet length mean': np.mean([p['size'] for p in fwd]) if fwd else 0,
            'fwd packet length std': np.std([p['size'] for p in fwd]) if fwd else 0,
            'bwd packet length mean': np.mean([p['size'] for p in bwd]) if bwd else 0,
            'bwd packet length std': np.std([p['size'] for p in bwd]) if bwd else 0,
            'flow packets/s': (count * 1e6) / dur,
            'flow bytes/s': (sum(p['size'] for p in self.packets) * 1e6) / dur,
            'fwd psh flags': sum(p['flags']['PSH'] for p in fwd),
            'ack flag count': sum(p['flags']['ACK'] for p in self.packets),
            'syn flag count': sum(p['flags']['SYN'] for p in self.packets),
            'fin flag count': sum(p['flags']['FIN'] for p in self.packets),
            'init_win_bytes_forward': fwd[0]['win_size'] if fwd else 0,
            'init_win_bytes_backward': bwd[0]['win_size'] if bwd else 0
        }
        return pd.DataFrame([feats], columns=FEATURE_COLS)

def process_packet(packet):
    global last_dos_reset_time, last_decay_time
    if not packet.haslayer(IP): return
    src_ip = packet[IP].src
    
    if src_ip in [MY_IP, GATEWAY_IP, "127.0.0.1"] or src_ip in BLOCKED_IPS:
        return

    current_time = time.time()
    
    # Giảm rủi ro theo thời gian (Leaky Bucket) - Chống chặn oan IP sạch
    if current_time - last_decay_time > 15.0:
        for ip in list(ip_risk_scores.keys()):
            if ip_risk_scores[ip] > 0:
                ip_risk_scores[ip] = max(0, ip_risk_scores[ip] - 0.1)
        last_decay_time = current_time

    # Heuristic DoS Check
    ip_packet_counts[src_ip] += 1
    if current_time - last_dos_reset_time > 2.0:
        ip_packet_counts.clear()
        last_dos_reset_time = current_time
    if ip_packet_counts[src_ip] > 400:
        block_ip(src_ip, "DoS / Traffic Flood")
        ip_packet_counts[src_ip] = 0 
        return

    # ==============================================================================
    # 4. CẢI TIẾN 3: KIỂM TRA TRẠNG THÁI TCP (CHỐNG TOOL QUÉT NHANH)
    # ==============================================================================
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if ('R' in flags or 'F' in flags) and ip_risk_scores[src_ip] > 0.05:
            ip_risk_scores[src_ip] += 0.05 

    # Xử lý luồng   
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    src_port = packet[TCP].sport if packet.haslayer(TCP) else 0
    dst_port = packet[TCP].dport if packet.haslayer(TCP) else 0
    
    flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
    reverse_key = (dst_ip, src_ip, dst_port, src_port, proto)
    
    if flow_key in active_flows:
        flow, dir = active_flows[flow_key], 0
    elif reverse_key in active_flows:
        flow, dir = active_flows[reverse_key], 1
    else:
        flow = active_flows[flow_key] = Flow(src_ip, dst_ip, src_port, dst_port, proto)
        dir = 0

    flow.add_packet(packet, dir)

    # --- DEBUG CHUẨN ---
    if packet.haslayer(TCP) and src_ip.startswith("192.168.73.") and dst_ip == MY_IP:
        tcp_flag = packet.sprintf('%TCP.flags%')
        print(f"[DEBUG] Gói TCP từ {src_ip} -> Cờ: {tcp_flag}")
    # -------------------

    # ==============================================================================
    # 5. AI PREDICTION 
    # ==============================================================================
    if len(flow.packets) >= MIN_PACKETS_TO_PREDICT:
        input_data = flow.extract_features()
        input_scaled = scaler.transform(input_data)
        score_benign = model.predict_proba(input_scaled)[0][0]
        
        suspicion = 1.0 - score_benign
        
        # Hạ độ nhạy, nếu thấy nghi ngờ lập tức cộng dồn
        if suspicion > 0.01:
            boost = 0.15 if suspicion > 0.2 else 0.0
            ip_risk_scores[src_ip] += (suspicion + boost)
            print(f"[AI_TRACK] {src_ip} | Risk: {ip_risk_scores[src_ip]:.2f} (Suspicion: {suspicion:.2f})")

        if ip_risk_scores[src_ip] >= RISK_THRESHOLD:
            block_ip(src_ip, f"Combined AI & Behavior Risk ({ip_risk_scores[src_ip]:.2f})")
            if flow_key in active_flows: del active_flows[flow_key]

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Vui lòng chạy với sudo!")
        sys.exit(1)

    log_thread = threading.Thread(target=monitor_auth_log, daemon=True)
    log_thread.start()

    print(f"--- HỆ THỐNG HIPS ĐA TẦNG ĐANG GIÁM SÁT {INTERFACE} ---")
    try:
        sniff(iface=INTERFACE, prn=process_packet, store=0, filter="ip")
    except KeyboardInterrupt:
        print("\n[STOP] Đã dừng.")
