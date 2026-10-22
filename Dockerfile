FROM python:3.12-slim

LABEL maintainer="NetPulse IPAM"
LABEL description="Scanner Réseau Local IPv4 & Application Web IPAM (DNS, ARP/MAC, Ports, Export CSV/PDF)"

# Installation des outils réseau nécessaires sous Linux (ping, iproute2, arp, résolution DNS)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    iproute2 \
    net-tools \
    dnsutils \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copie du code de l'application
COPY app.py scanner.py oui_db.py pdf_generator.py ./
COPY static/ ./static/

# Répertoire persistant pour la base de données SQLite (scans, historique, réservations)
RUN mkdir -p /data
VOLUME ["/data"]

ENV PYTHONUNBUFFERED=1
ENV IPAM_DATA_DIR=/data
ENV PORT=8080
ENV TZ=Europe/Paris

EXPOSE 8080

CMD ["python", "app.py"]
