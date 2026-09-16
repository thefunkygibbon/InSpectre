# Global ARG must be declared BEFORE the first FROM line
ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.19

# Stage 1: Build Frontend Static Assets natively on host architecture
FROM --platform=$BUILDPLATFORM node:20-alpine AS frontend-builder
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci || npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Main Home Assistant Image
FROM ${BUILD_FROM}

# Allow global pip installs on Alpine 3.19+
ENV PIP_BREAK_SYSTEM_PACKAGES=1

# Install Runtime System Dependencies
RUN apk add --no-cache \
    postgresql \
    postgresql-contrib \
    nginx \
    python3 \
    py3-pip \
    nmap \
    bind-tools \
    net-tools \
    libpq

# Set working directory and copy application source code
WORKDIR /app
COPY . /app/

# Install Python dependencies using temporary C-compiler tools
RUN apk add --no-cache --virtual .build-deps \
    gcc \
    musl-dev \
    python3-dev \
    libffi-dev \
    postgresql-dev && \
    pip install --no-cache-dir -r /app/backend/requirements.txt && \
    pip install --no-cache-dir -r /app/probe/requirements.txt && \
    apk del .build-deps

# Setup PostgreSQL Database directory & permissions
RUN mkdir -p /run/postgresql /var/lib/postgresql/data && \
    chown -R postgres:postgres /run/postgresql /var/lib/postgresql/data && \
    su postgres -c "initdb -D /var/lib/postgresql/data"

# Copy compiled frontend assets to Nginx web root directory
COPY --from=frontend-builder /build/dist /usr/share/nginx/html/

# Copy S6-overlay service definitions
COPY rootfs/ /