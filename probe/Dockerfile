FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap libpcap-dev gcc \
    avahi-utils \
    samba-common-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

CMD ["python", "main.py"]
