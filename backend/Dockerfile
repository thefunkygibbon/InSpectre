FROM python:3.12-slim

# Expose target architecture for multi-arch binary downloads
ARG TARGETARCH=amd64

# Install system tools + Trivy
RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping \
        traceroute \
        iproute2 \
        nmap \
        whois \
        dnsutils \
        curl \
        ca-certificates \
    && TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest \
        | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/' || echo "0.62.0") \
    && TRIVY_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "ARM64" || echo "64bit") \
    && curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin trivy 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]