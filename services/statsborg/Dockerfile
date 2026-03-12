FROM python:3.12-slim
WORKDIR /app
COPY app/ .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]
