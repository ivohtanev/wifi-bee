#!/usr/bin/env bash
# Separate monitor interface; NetworkManager and USB tethering remain running.
set -euo pipefail
IFACE=wlp44s0
MON=wifi_mon
ACTION=${1:-start}
if [[ $ACTION != start && $ACTION != stop && $ACTION != status ]]; then
  echo 'Usage: sudo ./wifi-monitor.sh [start|stop|status]' >&2; exit 2
fi
if [[ $ACTION == status ]]; then
  iw dev
  ip route show default
  exit
fi
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
if [[ $ACTION == stop ]]; then
  if iw dev "$MON" info >/dev/null 2>&1; then iw dev "$MON" del; fi
  echo 'Monitor interface removed. USB tethering unchanged.'
  exit
fi
rfkill unblock wlan
if rfkill list wifi | grep -q 'Hard blocked: yes'; then
  echo 'Wi-Fi is hardware-blocked. Enable it using the laptop switch/Fn key.' >&2
  exit 1
fi
if iw dev "$MON" info >/dev/null 2>&1; then
  ip link set "$MON" up
  echo "$MON already exists; inspect with: iw dev $MON info"
  exit
fi
PHY=$(iw dev "$IFACE" info | awk '$1 == "wiphy" {print "phy" $2}')
[[ -n $PHY ]] || { echo "Cannot find PHY for $IFACE" >&2; exit 1; }
iw phy "$PHY" interface add "$MON" type monitor
trap 'iw dev "$MON" del 2>/dev/null || true' ERR
ip link set "$MON" up
trap - ERR
iw dev "$MON" info
ip route show default
echo "Ready. Stop with: sudo ./wifi-monitor.sh stop"
