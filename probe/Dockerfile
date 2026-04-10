FROM python:3.12-slim

# nmap + network tools + iputils (ping) + traceroute
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap libpcap-dev gcc \
    avahi-utils \
    samba-common-bin \
    dnsutils \
    iputils-ping \
    traceroute \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

CMD ["python", "main.py"]
