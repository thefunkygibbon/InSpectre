ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.19

# Stage 1: Build Frontend
FROM --platform=$BUILDPLATFORM node:20-alpine AS frontend-builder
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Unified Production Image
FROM ${BUILD_FROM}

# Install packages
RUN apk add --no-cache postgresql postgresql-contrib nginx python3 py3-pip openssl su-exec

# Copy Python requirements & application source files
WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt --break-system-packages || \
    pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend/ /app/backend/
COPY probe/ /app/probe/
COPY --from=frontend-builder /build/dist /usr/share/nginx/html/

# Directory setup for Postgres and Nginx
RUN mkdir -p /run/nginx /run/postgresql /var/lib/postgresql/data && \
    chown -R postgres:postgres /run/postgresql /var/lib/postgresql

# Default environment variable so the backend never crashes on missing key
ENV SECRET_KEY="change_me_or_set_in_options"

WORKDIR /app