#!/usr/bin/env bash
# ==============================================================================
# Recon7 Remote Target Stacks (Automatic Let's Encrypt TLS via Caddy)
# ==============================================================================

set -e
ZONE="asia-southeast1-a"

echo "================================================================="
echo "[*] Configuring web1 (api.ojabo.org)..."
echo "================================================================="

gcloud compute ssh web1 --zone="$ZONE" --command='
mkdir -p ~/demo_target && cd ~/demo_target

cat <<EOF > docker-compose.yml
services:
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - vuln-api

  vuln-api:
    image: vulnerables/web-dvwa:latest
    restart: unless-stopped
    environment:
      - MYSQL_PASS=password

  redis-cache:
    image: redis:7-alpine
    restart: unless-stopped
    ports:
      - "6379:6379"

volumes:
  caddy_data:
  caddy_config:
EOF

cat <<EOF > Caddyfile
api.ojabo.org {
    reverse_proxy vuln-api:80
}
EOF

sudo docker compose down || true
sudo docker compose up -d
'

echo "================================================================="
echo "[*] Configuring web2 (dev.ojabo.org)..."
echo "================================================================="

gcloud compute ssh web2 --zone="$ZONE" --command='
mkdir -p ~/demo_target && cd ~/demo_target

cat <<EOF > docker-compose.yml
services:
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - php-app

  php-app:
    image: vulnerables/web-dvwa:latest
    restart: unless-stopped

  mysql-db:
    image: mariadb:10.5
    restart: unless-stopped
    ports:
      - "3306:3306"
    environment:
      - MYSQL_ROOT_PASSWORD=rootpassword
      - MYSQL_DATABASE=app_dev

volumes:
  caddy_data:
  caddy_config:
EOF

cat <<EOF > Caddyfile
dev.ojabo.org {
    reverse_proxy php-app:80
}
EOF

sudo docker compose down || true
sudo docker compose up -d
'

echo "================================================================="
echo "[*] Configuring web3 (staging.ojabo.org)..."
echo "================================================================="

gcloud compute ssh web3 --zone="$ZONE" --command='
mkdir -p ~/demo_target && cd ~/demo_target

cat <<EOF > docker-compose.yml
services:
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - juice-shop

  juice-shop:
    image: bkimminich/juice-shop:latest
    restart: unless-stopped

volumes:
  caddy_data:
  caddy_config:
EOF

cat <<EOF > Caddyfile
staging.ojabo.org {
    reverse_proxy juice-shop:3000
}
EOF

sudo docker compose down || true
sudo docker compose up -d
'

echo "================================================================="
echo "[+] ALL 3 DEMO TARGETS DEPLOYED SUCCESSFULLY!"
echo "================================================================="
