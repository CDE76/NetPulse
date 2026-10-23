FROM python:3.12-slim

LABEL maintainer="NetPulse IPAM"
LABEL org.opencontainers.image.source="https://github.com/CDE76/NetPulse"
LABEL org.opencontainers.image.description="NetPulse IPAM - Scanner Réseau Local IPv4, DNS, ARP/MAC, Wake-on-LAN, CSV & PDF"

# Installation des outils réseau nécessaires sous Linux (ping, iproute2, arp, résolution DNS)
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    iputils-ping \
    iproute2 \
    net-tools \
    dnsutils \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copie du code de l'application
COPY app.py scanner.py oui_db.py pdf_generator.py ./
COPY static/ ./static/

# Répertoire persistant pour la base de données SQLite (scans, historique, réservations, comptes)
RUN mkdir -p /data
VOLUME ["/data"]

ENV PYTHONUNBUFFERED=1
ENV IPAM_DATA_DIR=/data
ENV PORT=8095
ENV TZ=Europe/Paris

EXPOSE 8095

CMD ["python3", "/app/app.py"]
