FROM python:3.12-slim

# nmap + network tools + wget/unzip for Nuclei
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap libpcap-dev gcc \
    avahi-utils \
    samba-common-bin \
    dnsutils \
    iputils-ping \
    traceroute \
    iproute2 \
    iptables \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei vulnerability scanner
ARG NUCLEI_VERSION=3.3.7
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
         -O /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp/nuclei_unzip \
    && mv /tmp/nuclei_unzip/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei_unzip

# Pre-fetch Nuclei community templates (baked into image; rebuild to refresh)
RUN nuclei -update-templates -no-color 2>&1 | tail -5 || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
COPY vuln_scanner.py .
COPY mac-vendors-export.csv .

CMD ["python", "main.py"]
