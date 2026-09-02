# ==============================================================================
# Recon7 Demo Environment Provisioning Script (PowerShell for Windows)
# Target Zone: asia-southeast1-a | Series: E2 | Machine Type: e2-small
# ==============================================================================

$ZONE = "asia-southeast1-a"
$MACHINE_TYPE = "e2-small"
$IMAGE_FAMILY = "ubuntu-2204-lts"
$IMAGE_PROJECT = "ubuntu-os-cloud"
$FIREWALL_NAME = "allow-demo-all-traffic"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[*] Step 1: Creating All-Traffic Firewall Rule ($FIREWALL_NAME)..." -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

gcloud compute firewall-rules create $FIREWALL_NAME `
  --allow=tcp:1-65535,udp:1-65535,icmp `
  --source-ranges=0.0.0.0/0 `
  --target-tags=demo-server `
  --description="Allow all inbound traffic for Recon7 demo targets"

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[*] Step 2: Creating 3 VM Instances in $ZONE..." -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$StartupScript = @"
#!/bin/bash
set -e
if [ ! -f /swapfile ]; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release git ufw
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=`$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu `$(. /etc/os-release && echo "`$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable docker
systemctl start docker
"@

$tempStartup = "$env:TEMP\demo_startup.sh"
[System.IO.File]::WriteAllText($tempStartup, $StartupScript)

foreach ($VM in @("web1", "web2", "web3")) {
    Write-Host "[+] Provisioning $VM..." -ForegroundColor Green
    gcloud compute instances create $VM `
      --zone=$ZONE `
      --machine-type=$MACHINE_TYPE `
      --image-family=$IMAGE_FAMILY `
      --image-project=$IMAGE_PROJECT `
      --boot-disk-size=25GB `
      --boot-disk-type=pd-balanced `
      --tags=demo-server,http-server,https-server `
      --metadata-from-file="startup-script=$tempStartup"
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[*] Step 3: Fetching Public External IPs for Cloudflare DNS..." -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$IP_WEB1 = (gcloud compute instances describe web1 --zone=$ZONE --format="get(networkInterfaces[0].accessConfigs[0].natIP)").Trim()
$IP_WEB2 = (gcloud compute instances describe web2 --zone=$ZONE --format="get(networkInterfaces[0].accessConfigs[0].natIP)").Trim()
$IP_WEB3 = (gcloud compute instances describe web3 --zone=$ZONE --format="get(networkInterfaces[0].accessConfigs[0].natIP)").Trim()

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Yellow
Write-Host "               CLOUDFLARE DNS CONFIGURATION (A RECORDS)          " -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Yellow
Write-Host ("{0,-12} | {1,-24} | {2,-16}" -f "VM Name", "Domain Name", "External IP (A Record)")
Write-Host "-----------------------------------------------------------------"
Write-Host ("{0,-12} | {1,-24} | {2,-16}" -f "web1", "api.ojabo.org", $IP_WEB1) -ForegroundColor Green
Write-Host ("{0,-12} | {1,-24} | {2,-16}" -f "web2", "dev.ojabo.org", $IP_WEB2) -ForegroundColor Green
Write-Host ("{0,-12} | {1,-24} | {2,-16}" -f "web3", "staging.ojabo.org", $IP_WEB3) -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host ">> Add these 3 A records in Cloudflare now (Set Proxy status to 'DNS Only' / Grey Cloud for real reconnaissance)." -ForegroundColor Magenta
