FROM python:3.11-slim

# Install ping, traceroute, iputils, and nmap (required for vuln scanning)
RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping \
        traceroute \
        iproute2 \
        nmap \
        whois \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
