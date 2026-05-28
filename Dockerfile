FROM python:3.13-slim

RUN apt-get update && apt-get install -y     nmap suricata iw gcc g++ python3-dev     libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf-xlib-2.0-0     libcairo2 iproute2 iptables wget unzip     && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip &&     pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p chronicle logs reports/output reports/templates && chmod -R 777 chronicle logs reports
CMD ["python3", "obsidios.py", "--help"]
