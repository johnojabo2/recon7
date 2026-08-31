FROM python:3.11-slim

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies, nmap, masscan, libcap2-bin, git, curl, libpcap-dev
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    masscan \
    libcap2-bin \
    git \
    curl \
    ca-certificates \
    libimage-exiftool-perl \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Grant raw socket capability to nmap and masscan binaries without full root requirement
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap || true
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/masscan || true

# Install ProjectDiscovery tools (subfinder, httpx, nuclei)
RUN ARCH=$(dpkg --print-architecture) && \
    # subfinder
    curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_${ARCH}.zip -o /tmp/subfinder.zip && \
    busybox unzip /tmp/subfinder.zip -d /usr/local/bin/ && chmod +x /usr/local/bin/subfinder && rm /tmp/subfinder.zip || true && \
    # httpx
    curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_${ARCH}.zip -o /tmp/httpx.zip && \
    busybox unzip /tmp/httpx.zip -d /usr/local/bin/ && chmod +x /usr/local/bin/httpx && rm /tmp/httpx.zip || true && \
    # nuclei
    curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_${ARCH}.zip -o /tmp/nuclei.zip && \
    busybox unzip /tmp/nuclei.zip -d /usr/local/bin/ && chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip || true

WORKDIR /app

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

EXPOSE 8000

# Default entrypoint starts the API server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
