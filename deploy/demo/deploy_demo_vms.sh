#!/usr/bin/env bash
# ==============================================================================
# Recon7 Demo Environment Provisioning Script
# Target Zone: asia-southeast1-a | Series: E2 | Machine Type: e2-small
# ==============================================================================

set -e

REGION="asia-southeast1"
ZONE="asia-southeast1-a"
MACHINE_TYPE="e2-small"
IMAGE_FAMILY="ubuntu-2204-lts"
IMAGE_PROJECT="ubuntu-os-cloud"
FIREWALL_NAME="allow-demo-all-traffic"

echo "================================================================="
echo "[*] Step 1: Creating All-Traffic Firewall Rule ($FIREWALL_NAME)..."
echo "================================================================="
gcloud compute firewall-rules create "$FIREWALL_NAME" \
  --allow=tcp:1-65535,udp:1-65535,icmp \
  --source-ranges=0.0.0.0/0 \
  --target-tags=demo-server \
  --description="Allow all inbound traffic for Recon7 demo targets" \
  || echo "[!] Firewall rule '$FIREWALL_NAME' already exists. Continuing..."

# ------------------------------------------------------------------------------
# Startup Script: Installs Docker, Sets 2GB Swap, and Prepares Directory
# ------------------------------------------------------------------------------
cat <<'EOF' > /tmp/demo_startup.sh
#!/bin/bash
set -e

# 1. Setup 2GB Swap (Crucial for e2-small 2GB RAM stability)
if [ ! -f /swapfile ]; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# 2. Install Docker & Docker Compose
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release git ufw

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable docker
systemctl start docker
EOF

echo ""
echo "================================================================="
echo "[*] Step 2: Creating 3 VM Instances in $ZONE..."
echo "================================================================="

for VM in web1 web2 web3; do
  echo "[+] Provisioning $VM..."
  gcloud compute instances create "$VM" \
    --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --image-family="$IMAGE_FAMILY" \
    --image-project="$IMAGE_PROJECT" \
    --boot-disk-size=25GB \
    --boot-disk-type=pd-balanced \
    --tags=demo-server,http-server,https-server \
    --metadata-from-file=startup-script=/tmp/demo_startup.sh \
    || echo "[!] Instance $VM already exists or failed."
done

echo ""
echo "================================================================="
echo "[*] Step 3: Fetching Public External IPs for Cloudflare DNS..."
echo "================================================================="

IP_WEB1=$(gcloud compute instances describe web1 --zone="$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
IP_WEB2=$(gcloud compute instances describe web2 --zone="$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
IP_WEB3=$(gcloud compute instances describe web3 --zone="$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo ""
echo "================================================================="
echo "               CLOUDFLARE DNS CONFIGURATION (A RECORDS)          "
echo "================================================================="
printf "%-12s | %-24s | %-16s\n" "VM Name" "Domain Name" "External IP (A Record)"
echo "-----------------------------------------------------------------"
printf "%-12s | %-24s | %-16s\n" "web1" "api.ojabo.org" "$IP_WEB1"
printf "%-12s | %-24s | %-16s\n" "web2" "dev.ojabo.org" "$IP_WEB2"
printf "%-12s | %-24s | %-16s\n" "web3" "staging.ojabo.org" "$IP_WEB3"
echo "================================================================="
echo ""
echo ">> Add these 3 A records in Cloudflare now (Set Proxy status to DNS Only / Grey Cloud for direct scan)."
echo ""
