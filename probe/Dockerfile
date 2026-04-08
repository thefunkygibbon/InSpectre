FROM python:3.11-slim

# Install network tools and libpcap for Scapy
RUN apt-get update && apt-get install -y \
    nmap \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir scapy sqlalchemy psycopg2-binary

# Copy the code
COPY . .

# Run the scanner
CMD ["python", "main.py"]
