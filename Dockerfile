FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends     nmap arp-scan suricata iw gcc g++ python3-dev     libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf-xlib-2.0-0     libcairo2 iproute2 iptables wget unzip     && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip &&     pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p chronicle logs reports/output reports/backups reports/templates forge/rules /var/log/suricata /var/lib/suricata/rules \
    && touch /var/lib/suricata/rules/emerging-all.rules \
    && chmod 750 chronicle logs reports forge \
    && chmod 640 config/.env.example || true
# Least privilege: daemon needs root for raw sockets/iptables, but default
# to non-root so `dash`/`audit`/`backup` don't run as root by accident.
# Compose overrides user for daemon/sentinel/echo as needed.
RUN useradd -r -s /usr/sbin/nologin obsidios && chown -R obsidios:obsidios /app/chronicle /app/logs /app/reports /app/forge
USER obsidios
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/readyz', timeout=4)" || exit 1
CMD ["python3", "obsidios.py", "--help"]
