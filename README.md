# 🛡️ Hệ thống IPS Đa tầng tích hợp AI (Hybrid AI-IPS)

Đây là dự án Hệ thống phòng chống xâm nhập (IPS - Intrusion Prevention System) kiến trúc lai, kết hợp giữa mô hình học máy (Machine Learning) và các quy tắc giám sát hành vi mạng (Heuristic & Stateful Inspection). Hệ thống có khả năng tự động phát hiện, truy vết và ngăn chặn các cuộc tấn công Brute Force, DoS/DDoS và Botnet thời gian thực.

## ✨ Kiến trúc Phòng thủ 4 Lớp (Defense in Depth)

Hệ thống được thiết kế với tư duy phòng thủ chiều sâu, bảo vệ máy chủ qua 4 lớp:

* **Lớp 1 - Heuristic Engine (Chống DoS):** Đếm tần suất gói tin (Packet Rate). Tự động khóa các IP có lưu lượng xả rác bất thường (> 400 packets/2 giây).
* **Lớp 2 - Phân tích Nhật ký (Log Monitor):** Theo dõi file `/var/log/auth.log` theo thời gian thực để chặn ngay lập tức các cuộc tấn công Brute Force SSH dạng lén lút (Low & Slow).
* **Lớp 3 - AI Ensemble Model (Chống Brute Force Đa hình):** Mô hình Học máy dự đoán độ trượt (suspicion) dựa trên 21 đặc trưng mạng (Flow duration, IAT, Length...). Mô hình đạt độ chính xác **99.96%**.
* **Lớp 4 - Stateful TCP Limiting (Thuật toán Leaky Bucket):** Theo dõi cờ TCP (RST, FIN) để trừng phạt các công cụ dò quét nhanh. Kết hợp thuật toán **Leaky Bucket** (Tản nhiệt rủi ro) giúp trừ điểm các luồng mạng hợp lệ, **đảm bảo 0% False Positive (Không chặn nhầm)**.

---

## 📂 Cấu trúc Thư mục Dự án

* `ips_core.py`: Trái tim của hệ thống HIPS, giám sát và chặn IP thời gian thực.
* `models/`: Chứa mô hình AI (`ids_model.pkl`) và bộ chuẩn hóa dữ liệu (`ids_scaler.pkl`) đã được huấn luyện sẵn.
* `training_model/`: Chứa các notebook và kết quả tiền xử lý dữ liệu. Đặc biệt file `training_ensemble_model.ipynb` là mã nguồn huấn luyện mô hình Ensemble đạt độ chính xác 99.96%.
* `attack/`: Chứa các script giả lập tấn công `botnet_attack.sh` và `test_medium.txt` (file password) dùng cho máy Kali Linux.

---

## 🐧 Môi trường và thông tin các máy:
- Máy Kali: Máy tấn công - IP 192.168.73.134
- Máy Ubuntu: Máy mục tiêu và là máy tích hợp hệ thống IPS - AI - IP 192.168.73.137
- Hệ điều hành: Linux
- Môi trường: VMware Workstation
- Mạng: NAT

## 🐧 Hướng dẫn Cài đặt & Chạy trên Ubuntu (Máy Phòng thủ)

### 1. Clone repository và cài đặt môi trường

Mở terminal trên Ubuntu và chạy lần lượt các lệnh sau:

```bash
git clone https://github.com/VanThinh512/IPS_AI_App.git
cd AI_IPS_Project

# Tạo và kích hoạt môi trường ảo
python3 -m venv venv
source venv/bin/activate

# Cài đặt các thư viện cần thiết
pip install -r requirements.txt
```

### 2. Khởi chạy hệ thống IPS (Yêu cầu mở 3 Terminal)

Để quan sát toàn diện, hãy mở 3 cửa sổ Terminal riêng biệt trên Ubuntu:

* **Terminal 1 (Làm sạch Tường lửa):**
    ```bash
    sudo iptables -F
    ```
* **Terminal 2 (Khởi động IPS):**
    ```bash
    source venv/bin/activate
    sudo ./venv/bin/python ips_core.py
    ```
* **Terminal 3 (Giám sát Tường lửa thời gian thực):**
    Dùng để kiểm tra xem hệ thống đã thêm IP attacker vào danh sách chặn (DROP) hay chưa:
    ```bash
    sudo iptables -L -n
    ```

> **⚠️ Lưu ý:** Cần quyền `sudo` để IPS có thể ngửi gói tin (sniff) ở Layer 3 và thực thi các lệnh `iptables`.

---

## 🐉 Hướng dẫn tấn công trên Kali Linux (Máy Tấn công)

### 1. Chuẩn bị Kịch bản Tấn công

Copy thư mục `attack` từ dự án sang máy Kali Linux của bạn. Cấp quyền thực thi cho các kịch bản:

```bash
chmod +x attack/botnet_attack.sh
```

### 2. Các Kịch bản Demo Kiểm thử Hệ thống

* **Kịch bản 1: Botnet Magic Routing (Vượt mặt Firewall):**
    Script này giả lập mạng lưới Botnet, đổi IP liên tục (`.134`, `.135`, `.136`) và Brute Force bằng công cụ Hydra.
    ```bash
    sudo ./attack/botnet_attack.sh
    ```
    *-> Kết quả kỳ vọng: IPS truy vết và chặn độc lập từng IP giả mạo.*

* **Kịch bản 2: Tấn công Từ chối dịch vụ (TCP SYN Flood):**
    ```bash
    sudo hping3 -S -p 21 --flood <IP_Ubuntu>
    ```
    *-> Kết quả kỳ vọng: Lớp Heuristic chặn IP ngay lập tức trong vòng 1 giây.*

* **Kịch bản 3: Quét Mật khẩu Bạo lực (Brute Force):**
    Tấn công bằng Ncrack tạo hành vi phá kết nối TCP nhanh.
    ```bash
    ncrack -u admin -P attack/test_medium.txt ssh://<IP_Ubuntu>
    ```
    *-> Kết quả kỳ vọng: Lớp AI và TCP State phối hợp ép điểm rủi ro và chặn IP.*

