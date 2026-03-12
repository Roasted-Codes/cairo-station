#!/bin/sh
# Enable promiscuous mode so we see ALL bridge traffic, not just our own
ip link set eth0 promisc on
exec python3 -u /app/monitor.py
