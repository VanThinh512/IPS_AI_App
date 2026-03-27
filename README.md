# IPS AI App - Hướng dẫn chạy dự án

## 🐧 Trên Ubuntu

### 1. Clone repository và cài đặt môi trường

```bash
git clone <repo-url>
cd AI_IPS_Project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### 2. Chạy hệ thống (mở 3 terminal riêng)

#### Terminal 1: Reset iptables

```bash
sudo iptables -F
```

#### Terminal 2: Chạy IPS

```bash
sudo ./venv/bin/python ips_core.py
```

#### Terminal 3: Kiểm tra iptables

```bash
sudo iptables -L -n
```

---

## 🐉 Trên Kali Linux

### 1. Copy file attack

* Copy 2 file trong thư mục `attack` sang máy Kali

---

### 2. Chạy script tấn công

```bash
sudo ./botnet_attack.sh
```

---

## ⚠️ Lưu ý

* Cần quyền `sudo` để chạy iptables và IPS
* Đảm bảo đã kích hoạt môi trường `venv`
* Kiểm tra quyền thực thi cho script:

```bash
chmod +x botnet_attack.sh
```
