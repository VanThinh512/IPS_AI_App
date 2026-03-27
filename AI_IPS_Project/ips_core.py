import sys
import os
import time
import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, get_if_addr
from collections import defaultdict
import subprocess
import warnings

# Tắt cảnh báo để log sạch đẹp
warnings.filterwarnings("ignore")

# ==============================================================================
# 1. CẤU HÌNH HỆ THỐNG
# ==============================================================================
# Tên card mạng cần giám sát (Dùng lệnh 'ifconfig' hoặc 'ip a' để xem tên đúng)
# Trên VMware thường là 'ens33', 'eth0' hoặc 'lo' (nếu test nội bộ)
INTERFACE = "ens33" 
# [DYNAMIC IP] Tự động lấy IP của card mạng hiện tại
try:
    MY_IP = get_if_addr(INTERFACE)
    print(f"[INFO] Đã phát hiện IP của máy này (Whitelist): {MY_IP}")
except Exception as e:
    print(f"[ERROR] Không lấy được IP của {INTERFACE}. Đang dùng Localhost.")
    MY_IP = "127.0.0.1"
GATEWAY_IP = "192.168.73.1"
# Ngưỡng kích hoạt dự đoán (Để tránh dự đoán khi mới có 1 gói tin)
MIN_PACKETS_TO_PREDICT = 5  
BLOCK_THRESHOLD = 0.5       # Chỉ số tin cậy (nếu cần chỉnh threshold thủ công)

# Load các file mô hình (Đảm bảo đường dẫn đúng)
try:
    print("[INIT] Đang tải mô hình AI...")
    model = joblib.load('models/ids_model.pkl')
    scaler = joblib.load('models/ids_scaler.pkl')
    # Label encoder có thể không cần thiết nếu ta chỉ quan tâm 0 là Benign, >0 là Attack
    # le = joblib.load('models/ids_label_encoder.pkl') 
    print("[INIT] Tải mô hình thành công!")
except Exception as e:
    print(f"[ERROR] Không tìm thấy file model! Lỗi: {e}")
    sys.exit(1)

# Danh sách Features ĐÚNG THỨ TỰ bạn đã cung cấp
FEATURE_COLS = [
    'flow duration', 'flow iat mean', 'flow iat std', 'flow iat max', 'flow iat min',
    'fwd iat mean', 'fwd iat std', 'total fwd packets', 'total backward packets',
    'fwd packet length mean', 'fwd packet length std', 'bwd packet length mean',
    'bwd packet length std', 'flow packets/s', 'flow bytes/s', 'fwd psh flags',
    'ack flag count', 'syn flag count', 'fin flag count', 'init_win_bytes_forward',
    'init_win_bytes_backward'
]

# Danh sách IP đã chặn để tránh chạy lệnh chặn lặp lại
BLOCKED_IPS = set()

# ==============================================================================
# 2. LỚP XỬ LÝ LUỒNG (FLOW TRACKER)
# ==============================================================================
class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        
        self.start_time = time.time()
        self.last_time = self.start_time
        self.packets = [] # Lưu danh sách (timestamp, size, direction, flags)
        
        # Direction: 0 = Forward (Src->Dst), 1 = Backward (Dst->Src)

    def add_packet(self, packet, direction):
        current_time = time.time()
        
        # Lấy size
        size = len(packet)
        
        # Lấy Flags (chỉ TCP mới có)
        flags = {
            'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'ECE': 0, 'CWR': 0
        }
        if packet.haslayer(TCP):
            f = packet[TCP].flags
            if 'F' in f: flags['FIN'] = 1
            if 'S' in f: flags['SYN'] = 1
            if 'P' in f: flags['PSH'] = 1
            if 'A' in f: flags['ACK'] = 1
        
        # Lấy Window Size
        win_size = packet[TCP].window if packet.haslayer(TCP) else 0

        # Lưu thông tin gói
        self.packets.append({
            'time': current_time,
            'size': size,
            'direction': direction, # 0: Fwd, 1: Bwd
            'flags': flags,
            'win_size': win_size
        })
        self.last_time = current_time

    def extract_features(self):
        # Tính toán các đặc trưng thống kê từ danh sách packets
        count = len(self.packets)
        if count == 0: return None
        
        # 1. Flow Duration (Microseconds - giống dataset gốc)
        flow_duration = (self.packets[-1]['time'] - self.packets[0]['time']) * 1e6
        if flow_duration == 0: flow_duration = 1 # Tránh chia cho 0

        # Tách gói Fwd và Bwd
        fwd_pkts = [p for p in self.packets if p['direction'] == 0]
        bwd_pkts = [p for p in self.packets if p['direction'] == 1]
        
        # --- IAT (Inter-Arrival Time) Calculation ---
        timestamps = [p['time'] * 1e6 for p in self.packets] # Convert to microsec
        iats = np.diff(timestamps) if len(timestamps) > 1 else [0]
        
        fwd_timestamps = [p['time'] * 1e6 for p in fwd_pkts]
        fwd_iats = np.diff(fwd_timestamps) if len(fwd_timestamps) > 1 else [0]

        # --- Packet Length Calculation ---
        fwd_sizes = [p['size'] for p in fwd_pkts] if fwd_pkts else [0]
        bwd_sizes = [p['size'] for p in bwd_pkts] if bwd_pkts else [0]
        
        # --- Flag Counts ---
        fwd_psh = sum(p['flags']['PSH'] for p in fwd_pkts)
        total_ack = sum(p['flags']['ACK'] for p in self.packets)
        total_syn = sum(p['flags']['SYN'] for p in self.packets)
        total_fin = sum(p['flags']['FIN'] for p in self.packets)
        
        # --- Window Bytes ---
        # Lấy window size của gói đầu tiên trong mỗi hướng (approx init window)
        init_win_fwd = fwd_pkts[0]['win_size'] if fwd_pkts else 0
        init_win_bwd = bwd_pkts[0]['win_size'] if bwd_pkts else 0

        # --- MAPPING VÀO ĐÚNG 21 CỘT ---
        feats = {
            'flow duration': flow_duration,
            'flow iat mean': np.mean(iats),
            'flow iat std': np.std(iats),
            'flow iat max': np.max(iats),
            'flow iat min': np.min(iats),
            
            'fwd iat mean': np.mean(fwd_iats),
            'fwd iat std': np.std(fwd_iats),
            
            'total fwd packets': len(fwd_pkts),
            'total backward packets': len(bwd_pkts),
            
            'fwd packet length mean': np.mean(fwd_sizes),
            'fwd packet length std': np.std(fwd_sizes),
            'bwd packet length mean': np.mean(bwd_sizes),
            'bwd packet length std': np.std(bwd_sizes),
            
            'flow packets/s': (count * 1e6) / flow_duration,
            'flow bytes/s': (sum(p['size'] for p in self.packets) * 1e6) / flow_duration,
            
            'fwd psh flags': fwd_psh,
            'ack flag count': total_ack,
            'syn flag count': total_syn,
            'fin flag count': total_fin,
            
            'init_win_bytes_forward': init_win_fwd,
            'init_win_bytes_backward': init_win_bwd
        }
        
        # Chuyển về DataFrame đúng thứ tự cột
        return pd.DataFrame([feats], columns=FEATURE_COLS)

# Lưu trữ các luồng đang hoạt động: Key = (SrcIP, DstIP, SrcPort, DstPort, Proto)
active_flows = {}
# [MỚI] Bảng theo dõi điểm rủi ro tích lũy của từng IP
ip_risk_scores = defaultdict(float)
# ==============================================================================
# 3. CHỨC NĂNG CHẶN VÀ DỰ ĐOÁN
# ==============================================================================
def block_ip(ip_address, attack_type):
    if ip_address in BLOCKED_IPS:
        return # Đã chặn rồi thì thôi
    
    print(f"\n[ALERT] PHÁT HIỆN TẤN CÔNG TỪ {ip_address} !!!")
    print(f"        Loại tấn công: {attack_type}")
    print(f"        -> Đang thực thi chặn IP...")
    
    # Lệnh chặn IP trên Linux bằng iptables
    try:
        cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
        subprocess.run(cmd.split(), check=True)
        BLOCKED_IPS.add(ip_address)
        print(f"[SUCCESS] Đã chặn thành công IP: {ip_address}\n")
    except Exception as e:
        print(f"[FAIL] Lỗi khi chặn IP (Bạn có chạy sudo chưa?): {e}")

def process_packet(packet):
    print(f".", end="", flush=True) 
    
    if not packet.haslayer(IP): return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    
    # <--- SỬA CHỖ NÀY: WHITELIST (DANH SÁCH TRẮNG) --->
    # Bỏ qua nếu IP nguồn là Localhost HOẶC là chính máy Ubuntu này (Dynamic IP)
    if src_ip == "127.0.0.1" or src_ip == MY_IP or src_ip == GATEWAY_IP: 
        return
    # <------------------------------------------------->

    src_port = 0
    dst_port = 0
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else: return 

    # Quản lý luồng
    flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
    reverse_key = (dst_ip, src_ip, dst_port, src_port, proto)
    
    direction = 0 
    current_key = flow_key
    
    if flow_key in active_flows:
        current_key = flow_key
        direction = 0
    elif reverse_key in active_flows:
        current_key = reverse_key
        direction = 1
    else:
        active_flows[flow_key] = Flow(src_ip, dst_ip, src_port, dst_port, proto)
        current_key = flow_key
        direction = 0

    flow = active_flows[current_key]
    flow.add_packet(packet, direction)
    
    # --- DỰ ĐOÁN & CỘNG DỒN RỦI RO ---
    if len(flow.packets) >= MIN_PACKETS_TO_PREDICT:
        if len(flow.packets) % 5 != 0: return

        # 1. AI Dự đoán
        input_data = flow.extract_features()
        input_scaled = scaler.transform(input_data)
        probs = model.predict_proba(input_scaled)[0]
        
        score_benign = probs[0]
        
        # 2. TÍNH ĐIỂM NGHI NGỜ
        current_suspicion = 1.0 - score_benign
        
        # 3. CỘNG DỒN VÀO "SỔ NỢ" CỦA IP
        if current_suspicion > 0.01:
            # Cộng dồn mạnh tay hơn để chặn nhanh (0.2)
            ip_risk_scores[src_ip] += (current_suspicion + 0.1)
        
        print(f"\n[RISK_TRACK] {src_ip} | Suspicion: {current_suspicion:.2f} | ACCUMULATED RISK: {ip_risk_scores[src_ip]:.2f}")

        # 4. LOGIC CHẶN CỰC NHANH (FAST BLOCK)
        RISK_THRESHOLD = 0.5
        
        if ip_risk_scores[src_ip] > RISK_THRESHOLD:
            block_ip(src_ip, f"Cumulative Risk (Score: {ip_risk_scores[src_ip]:.2f})")
            
            if src_ip in ip_risk_scores:
                del ip_risk_scores[src_ip]
            
            if current_key in active_flows:
                del active_flows[current_key]
            return

# ==============================================================================
# 4. MAIN LOOP
# ==============================================================================
if __name__ == "__main__":
    # Check quyền root
    if os.geteuid() != 0:
        print("[WARNING] Vui lòng chạy bằng quyền ROOT (sudo) để có thể chặn IP!")
        sys.exit(1)

    print(f"--- HỆ THỐNG IPS AI BẮT ĐẦU GIÁM SÁT TRÊN {INTERFACE} ---")
    print(f"--- Đang đợi gói tin... (Nhấn Ctrl+C để dừng) ---")
    
    try:
        # Bắt gói tin và gọi hàm callback 'process_packet'
        sniff(iface=INTERFACE, prn=process_packet, store=0, filter="ip", promisc=True)
    except KeyboardInterrupt:
        print("\n[STOP] Đã dừng hệ thống.")
