FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends dnsutils curl netcat-openbsd && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY server.py .
EXPOSE 8080
CMD ["python3", "server.py"]
