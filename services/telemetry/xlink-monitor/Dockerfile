FROM python:3.12-alpine

RUN apk add --no-cache tcpdump iproute2

COPY monitor.py /app/monitor.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
