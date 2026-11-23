#!/usr/bin/env bash
# Threat Origin Map — one-command install / update for Linux.
#   ./install.sh        asks 3 questions the first time, then builds and starts everything
#   ./install.sh -y     no questions: plain HTTP on port 9595, syslog on 5514
#   ./install.sh -r     ask the questions again (domain, syslog port, Suricata folder)
# Re-run it any time to update; your settings (in the Docker volume) are kept.
set -euo pipefail
cd "$(dirname "$0")"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mHata:\033[0m %s\n' "$*" >&2; exit 1; }
ask()  { local q=$1 def=${2:-}; if [ "$YES" = 1 ]; then REPLY=$def; else read -rp "$q " REPLY; REPLY=${REPLY:-$def}; fi; }

YES=0; RECONF=0
case "${1:-}" in -y) YES=1 ;; -r) RECONF=1 ;; esac
if [ "$RECONF" = 1 ] && [ -f .env ]; then
  mv .env .env.bak
  say "Önceki ayarlar .env.bak dosyasına alındı; sorular yeniden soruluyor."
fi
if [ -f .env ]; then
  say "Mevcut ayarlar kullanılıyor ($(grep -E '^(DOMAIN|SYSLOG_PORT|HTTP_PORT)=' .env | tr '\n' ' '))"
  say "Bunları değiştirmek için: ./install.sh -r"
fi
SUDO=""; [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

# ---- Docker
if ! command -v docker >/dev/null 2>&1; then
  say "Docker bulunamadı."
  ask "Docker, resmi kurulum betiğiyle (get.docker.com) kurulsun mu? [e/H]" "h"
  case "$REPLY" in e|E|y|Y) curl -fsSL https://get.docker.com | $SUDO sh ;;
    *) die "Docker'ı kurup tekrar çalıştırın: https://docs.docker.com/engine/install/" ;; esac
fi
DOCKER="docker"; docker info >/dev/null 2>&1 || DOCKER="$SUDO docker"
$DOCKER info >/dev/null 2>&1 || die "Docker çalışmıyor. 'sudo systemctl start docker' deneyin."
$DOCKER compose version >/dev/null 2>&1 || die "Docker Compose eklentisi gerekli (docker-compose-plugin paketi)."

# ---- first run: three questions -> .env
if [ ! -f .env ]; then
  say "İlk kurulum. Boş bırakılan sorular varsayılanı kullanır."
  ask "Alan adı (HTTPS için, ör. attackmap.firma.com; boş = http://SUNUCU_IP:9595):" ""
  DOMAIN=${REPLY#*://}; DOMAIN=${DOMAIN%%/*}; DOMAIN=${DOMAIN%%:*}  # "https://x.com:9595/" -> "x.com"
  [ -z "$DOMAIN" ] || [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$ ]] \
    || die "Alan adı yalnızca ad olmalı, ör. attackmap.firma.com (https:// ve port yazmayın)."
  ask "Syslog UDP portu [5514]:" "5514"
  SYSLOG_PORT=$REPLY
  ask "Suricata bu sunucudaysa log klasörü (ör. /var/log/suricata; boş = yok):" ""
  EVE_DIR=$REPLY
  [[ "$SYSLOG_PORT" =~ ^[0-9]+$ ]] || die "Port bir sayı olmalı."
  [ -z "$EVE_DIR" ] || [ -d "$EVE_DIR" ] || die "$EVE_DIR klasörü yok."
  {
    echo "# Written by install.sh. Everything else is set in the web UI."
    echo "SYSLOG_PORT=$SYSLOG_PORT"
    echo "EVE_DIR=${EVE_DIR:-./eve}"
    if [ -n "$DOMAIN" ]; then
      echo "DOMAIN=$DOMAIN"
      echo "COMPOSE_PROFILES=https"
      echo "HTTP_BIND=127.0.0.1"
      echo "HTTP_PORT=9595"
      echo "TRUST_PROXY=1"
    else
      echo "HTTP_BIND=0.0.0.0"
      echo "HTTP_PORT=9595"
    fi
  } > .env
fi
mkdir -p eve
set -a; . ./.env; set +a

# ---- build + start
say "İmaj hazırlanıyor ve başlatılıyor…"
$DOCKER compose up -d --build
# HTTPS turned off on a re-run: the old proxy container would otherwise keep holding ports 80/443
[ -n "${DOMAIN:-}" ] || $DOCKER rm -f attack-map-https >/dev/null 2>&1 || true

say "Servisin açılması bekleniyor…"
for _ in $(seq 1 60); do
  $DOCKER compose logs attack-map 2>/dev/null | grep -q "Attack map on" && break
  sleep 1
done

# ---- open firewall ports if ufw is active
if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -q "Status: active"; then
  say "ufw açık: portlar ekleniyor"
  $SUDO ufw allow "${SYSLOG_PORT}/udp" >/dev/null
  if [ -n "${DOMAIN:-}" ]; then $SUDO ufw allow 80/tcp >/dev/null; $SUDO ufw allow 443/tcp >/dev/null
  else $SUDO ufw allow "${HTTP_PORT}/tcp" >/dev/null; fi
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}'); IP=${IP:-SUNUCU_IP}
URL="http://$IP:${HTTP_PORT}"; [ -n "${DOMAIN:-}" ] && URL="https://$DOMAIN"
CODE=$($DOCKER compose logs attack-map 2>/dev/null | grep -o 'SETUP CODE: [A-F0-9-]*' | tail -1 | cut -d' ' -f3 || true)

echo
printf '\033[1;32m✔ Kurulum tamam.\033[0m\n\n'
echo "  Harita adresi : $URL"
echo "  Syslog hedefi : $IP:${SYSLOG_PORT} (UDP)"
if [ -n "$CODE" ]; then
  echo "  Kurulum kodu  : $CODE"
  echo
  echo "  Adresi tarayıcıda açın, kurulum kodunu girin ve gerisini ekrandan ayarlayın."
else
  echo
  echo "  Kurulum daha önce tamamlanmış; ayarlarınız korundu."
fi
echo
