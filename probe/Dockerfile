FROM python:3.12-slim

# nmap + network tools + wget/unzip for Nuclei
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev gcc \
    nmap \
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
ARG NUCLEI_VERSION=3.4.4
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
         -O /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp/nuclei_unzip \
    && mv /tmp/nuclei_unzip/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei_unzip

# Install Nerva service fingerprinting tool (graceful failure — probe handles absence)
ARG NERVA_VERSION=1.3.0
RUN wget -q "https://github.com/praetorian-inc/nerva/releases/download/v${NERVA_VERSION}/nerva-linux-amd64.tar.gz" \
         -O /tmp/nerva.tar.gz \
    && tar -xzf /tmp/nerva.tar.gz -C /tmp/ \
    && mv /tmp/nerva /usr/local/bin/nerva \
    && chmod +x /usr/local/bin/nerva \
    && rm -f /tmp/nerva.tar.gz \
    || echo "[WARN] Nerva download failed — service fingerprinting will be skipped"

# Pre-fetch Nuclei community templates (baked into image; rebuild to refresh)
RUN nuclei -update-templates -no-color 2>&1 | tail -5 || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
COPY vuln_scanner.py .
COPY traffic_monitor.py .
COPY mac-vendors-export.csv .

# Download GeoLite2-Country database if MAXMIND_LICENSE_KEY is provided at build time.
# Without it, GeoIP lookups are silently skipped.
ARG MAXMIND_LICENSE_KEY=""
RUN if [ -n "$MAXMIND_LICENSE_KEY" ]; then \
      mkdir -p /opt/geoip && \
      wget -q "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" \
           -O /tmp/geolite2.tar.gz && \
      tar -xzf /tmp/geolite2.tar.gz -C /tmp/ && \
      mv /tmp/GeoLite2-Country_*/GeoLite2-Country.mmdb /opt/geoip/ && \
      rm -rf /tmp/geolite2.tar.gz /tmp/GeoLite2-Country_*; \
    else \
      echo "[INFO] MAXMIND_LICENSE_KEY not set — GeoIP skipped"; \
    fi

CMD ["python", "main.py"]
