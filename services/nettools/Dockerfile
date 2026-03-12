# syntax=docker/dockerfile:1

FROM alpine:3.19

LABEL maintainer="Roasted-Codes"
LABEL description="Network diagnostic tools for xemu_lan telemetry"

RUN apk add --no-cache \
    iperf3 \
    mtr \
    traceroute \
    bind-tools \
    curl \
    tcpdump \
    ethtool \
    bash \
    nmap-ncat \
    libcap

# Create non-root user for running tools
RUN adduser -D -u 1000 nettools

# Grant raw socket capabilities to binaries that need them
# so they work without running as root
RUN setcap cap_net_raw+eip /usr/sbin/mtr-packet && \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump

USER nettools

# Default: iperf3 server on port 5201
# For manual tools: docker exec -it xemu-nettools mtr -rwbz <target>
ENTRYPOINT ["iperf3"]
CMD ["-s"]
