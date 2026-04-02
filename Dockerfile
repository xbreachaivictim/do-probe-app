FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl dnsutils netcat-openbsd iproute2 procps && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY server.py .
EXPOSE 8080
CMD ["python3", "server.py"]
