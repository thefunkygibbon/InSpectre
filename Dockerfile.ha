ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.19
FROM ${BUILD_FROM}

RUN apk add --no-cache \
    postgresql \
    postgresql-contrib \
    nginx \
    python3 \
    py3-pip \
    nmap \
    bind-tools \
    net-tools

RUN mkdir -p /run/postgresql /var/lib/postgresql/data && \
    chown -R postgres:postgres /run/postgresql /var/lib/postgresql/data && \
    su postgres -c "initdb -D /var/lib/postgresql/data"

WORKDIR /app
COPY . /app/

RUN pip install --no-cache-dir -r /app/backend/requirements.txt || true
RUN pip install --no-cache-dir -r /app/probe/requirements.txt || true

COPY rootfs/ /