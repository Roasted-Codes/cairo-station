# syntax=docker/dockerfile:1

FROM lscr.io/linuxserver/xemu:latest

# set version label
LABEL maintainer="Roasted-Codes"

# Install additional packages for window automation, networking, and pcap shim compilation
RUN \
  apt-get update && \
  apt-get install -y --no-install-recommends \
    wmctrl \
    ethtool \
    gcc \
    libpcap-dev && \
  apt-get autoclean && \
  rm -rf \
    /var/lib/apt/lists/* \
    /var/tmp/* \
    /tmp/*

# Compile pcap immediate mode shim into the image.
# Without this, xemu's pcap backend can send packets but never receives them
# (libpcap >= 1.9 with TPACKET_V3: the selectable fd never becomes readable
# without immediate mode). The shim intercepts pcap_open_live() and injects
# pcap_set_immediate_mode(1). Baked into the image so it survives volume wipes.
COPY data/emulator/pcap_immediate.c /tmp/pcap_immediate.c
RUN gcc -shared -fPIC -o /opt/pcap_immediate.so /tmp/pcap_immediate.c -lpcap && \
    rm /tmp/pcap_immediate.c

# Replace upstream autostart with custom version
COPY root/defaults/autostart /defaults/autostart
