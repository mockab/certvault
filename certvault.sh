#!/bin/bash
# CertVault - Certificate Management System
# Startup, Install & HTTPS Setup Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
PID_FILE="$SCRIPT_DIR/certvault.pid"
LOG_FILE="$SCRIPT_DIR/certvault.log"
HTTPS_CONF="$SCRIPT_DIR/.https.conf"
PORT="${PORT:-5000}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "  ╔════════════════════════════════════════╗"
  echo "  ║          🔐  CertVault v1.1            ║"
  echo "  ║    Certificate Management System       ║"
  echo "  ╚════════════════════════════════════════╝"
  echo -e "${NC}"
}

info()    { echo -e "  ${CYAN}→${NC} $*"; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $*"; }
err_msg() { echo -e "  ${RED}✗${NC} $*"; }
die()     { err_msg "$*"; exit 1; }
section() { echo -e "\n  ${BOLD}${YELLOW}── $* ──${NC}"; }

# Find the cert dir — always uses sudo since /etc/letsencrypt is root-owned
_find_cert_dir() {
  local domain="$1"
  local cert_name="$2"   # optional: saved cert name from .https.conf

  # Try saved cert name first (fastest path)
  if [ -n "$cert_name" ] && sudo test -f "/etc/letsencrypt/live/${cert_name}/fullchain.pem" 2>/dev/null; then
    echo "/etc/letsencrypt/live/${cert_name}"
    return
  fi
  # Try 'certvault' (the name we ask certbot to use)
  if sudo test -f "/etc/letsencrypt/live/certvault/fullchain.pem" 2>/dev/null; then
    echo "/etc/letsencrypt/live/certvault"
    return
  fi
  # Try the domain name (certbot sometimes uses this instead)
  if [ -n "$domain" ] && sudo test -f "/etc/letsencrypt/live/${domain}/fullchain.pem" 2>/dev/null; then
    echo "/etc/letsencrypt/live/${domain}"
    return
  fi
  # Last resort: search all of /etc/letsencrypt/live with sudo
  local found
  found=$(sudo find /etc/letsencrypt/live -maxdepth 2 -name "fullchain.pem" 2>/dev/null \
    | head -1 | xargs -I{} dirname {} 2>/dev/null || true)
  if [ -n "$found" ]; then
    echo "$found"
    return
  fi
  return 1
}

# ─── Install ──────────────────────────────────────────────────────────────────
cmd_install() {
  banner
  section "Installing CertVault"

  command -v python3 &>/dev/null || die "Python 3 required. Run: sudo apt install python3 python3-venv"

  info "Creating virtual environment..."
  python3 -m venv "$VENV_DIR"

  info "Installing Python dependencies..."
  "$VENV_DIR/bin/pip" install --quiet flask cryptography 2>&1 | grep -v "^$" || true

  ok "Installation complete!"
  echo ""
  echo -e "  Start CertVault:   ${CYAN}./certvault.sh start${NC}"
  echo -e "  Set up HTTPS:      ${CYAN}./certvault.sh https-setup${NC}"
}

# ─── Start / Stop ─────────────────────────────────────────────────────────────
_print_url() {
  if [ -f "$HTTPS_CONF" ]; then
    # shellcheck disable=SC1090
    source "$HTTPS_CONF"
    echo -e "  Open: ${CYAN}https://$CV_DOMAIN${NC}"
  else
    echo -e "  Open: ${CYAN}http://localhost:$PORT${NC}"
  fi
}

cmd_start() {
  banner

  [ -d "$VENV_DIR" ] || { warn "venv not found — running install first..."; cmd_install; }

  if [ -f "$PID_FILE" ]; then
    local pid
    pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
      warn "CertVault already running (PID $pid)"
      _print_url; return
    fi
    rm -f "$PID_FILE"
  fi

  local bind_host="0.0.0.0"
  local bind_port="$PORT"
  if [ -f "$HTTPS_CONF" ]; then
    # shellcheck disable=SC1090
    source "$HTTPS_CONF"
    bind_host="127.0.0.1"
    bind_port="$CV_PORT"
  fi

  section "Starting CertVault"
  cd "$SCRIPT_DIR"
  FLASK_HOST="$bind_host" PORT="$bind_port" \
    nohup "$VENV_DIR/bin/python" app.py >> "$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  sleep 1

  if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    ok "CertVault started (PID $(cat "$PID_FILE"))"
    echo ""
    _print_url
    echo -e "  Logs: ${CYAN}./certvault.sh logs${NC}"
    echo -e "  Stop: ${CYAN}./certvault.sh stop${NC}"
  else
    die "Failed to start — check logs: $LOG_FILE"
  fi
}

cmd_stop() {
  if [ -f "$PID_FILE" ]; then
    local pid
    pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" && rm -f "$PID_FILE"
      ok "CertVault stopped"
    else
      echo "CertVault is not running"; rm -f "$PID_FILE"
    fi
  else
    echo "CertVault is not running"
  fi
}

cmd_restart() { cmd_stop; sleep 1; cmd_start; }

cmd_status() {
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    ok "CertVault is running (PID $(cat "$PID_FILE"))"
    _print_url
  else
    warn "CertVault is not running"
    [ -f "$PID_FILE" ] && rm -f "$PID_FILE"
  fi
}

cmd_foreground() {
  banner
  [ -d "$VENV_DIR" ] || cmd_install

  local bind_host="0.0.0.0"
  local bind_port="$PORT"
  if [ -f "$HTTPS_CONF" ]; then
    # shellcheck disable=SC1090
    source "$HTTPS_CONF"
    bind_host="127.0.0.1"
    bind_port="$CV_PORT"
  fi

  cd "$SCRIPT_DIR"
  info "Starting in foreground on ${bind_host}:${bind_port} (Ctrl+C to stop)..."
  exec FLASK_HOST="$bind_host" PORT="$bind_port" "$VENV_DIR/bin/python" app.py
}

cmd_logs() {
  [ -f "$LOG_FILE" ] && tail -f "$LOG_FILE" || echo "No log file at $LOG_FILE"
}

# ─── HTTPS Setup: Certbot + Cloudflare DNS + Nginx ───────────────────────────
cmd_https_setup() {
  banner
  section "HTTPS Setup — Let's Encrypt + Cloudflare DNS + Nginx"

  echo ""
  echo "  This will:"
  echo "   1. Obtain a TLS certificate via Let's Encrypt (Cloudflare DNS-01 challenge)"
  echo "   2. Install and configure nginx as an HTTPS reverse proxy"
  echo "   3. Redirect HTTP → HTTPS automatically"
  echo "   4. Set Flask to listen on localhost only (nginx handles external traffic)"
  echo "   5. Install a daily cron job to auto-renew the certificate"
  echo ""

  # ── Inputs ────────────────────────────────────────────────────────────────
  read -rp "  Domain name for CertVault (e.g. certs.example.com): " CV_DOMAIN
  [[ -n "$CV_DOMAIN" ]] || die "Domain is required"

  read -rp "  Email for Let's Encrypt expiry notices: " CV_EMAIL
  [[ -n "$CV_EMAIL" ]] || die "Email is required"

  echo ""
  echo -e "  ${YELLOW}Cloudflare API Token${NC}"
  echo "  Create at: https://dash.cloudflare.com/profile/api-tokens"
  echo "  Permissions needed: Zone → Zone (Read)  +  Zone → DNS (Edit)"
  echo ""
  read -rsp "  Cloudflare API token: " CF_TOKEN
  echo ""
  [[ -n "$CF_TOKEN" ]] || die "Cloudflare API token is required"

  read -rp "  Internal Flask port [${PORT}]: " INPUT_PORT
  CV_PORT="${INPUT_PORT:-$PORT}"

  echo ""
  echo -e "  ${BOLD}Confirm:${NC}"
  echo -e "    Domain:     ${CYAN}$CV_DOMAIN${NC}"
  echo -e "    Email:      ${CYAN}$CV_EMAIL${NC}"
  echo -e "    CF Token:   ${CYAN}${CF_TOKEN:0:6}…${NC}"
  echo -e "    Flask port: ${CYAN}$CV_PORT${NC} (internal, localhost only after setup)"
  echo ""
  read -rp "  Proceed? [y/N] " CONFIRM
  [[ "${CONFIRM,,}" == "y" ]] || { echo "Aborted."; exit 0; }

  # ── System packages ───────────────────────────────────────────────────────
  section "Installing system packages"

  command -v apt-get &>/dev/null || die "apt-get not found — Debian/Ubuntu required"
  sudo apt-get update -q

  _apt() {
    dpkg -s "$1" &>/dev/null \
      && ok "$1 already installed" \
      || { info "Installing $1..."; sudo apt-get install -y -q "$1"; ok "$1 installed"; }
  }

  _apt nginx
  _apt certbot
  _apt python3-certbot-dns-cloudflare

  # ── Cloudflare credentials ────────────────────────────────────────────────
  section "Writing Cloudflare credentials"

  CF_INI="$SCRIPT_DIR/.cf-credentials.ini"
  cat > "$CF_INI" << EOF
# Cloudflare API credentials — generated by certvault.sh
dns_cloudflare_api_token = ${CF_TOKEN}
EOF
  chmod 600 "$CF_INI"
  ok "Credentials saved to $CF_INI (permissions: 600)"

  # ── Obtain certificate ────────────────────────────────────────────────────
  section "Obtaining certificate from Let's Encrypt"
  info "Running certbot — DNS propagation may take ~30 seconds..."
  echo ""

  sudo certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials "$CF_INI" \
    --dns-cloudflare-propagation-seconds 30 \
    --email "$CV_EMAIL" \
    --agree-tos \
    --non-interactive \
    --cert-name certvault \
    -d "$CV_DOMAIN" 2>&1 | sed 's/^/    /'

  echo ""

  # Detect actual cert dir — /etc/letsencrypt is root-owned, use sudo
  CERT_DIR=$(_find_cert_dir "$CV_DOMAIN" "certvault") \
    || die "Certificate not found in /etc/letsencrypt/live — certbot may have failed above"

  ok "Certificate found at: $CERT_DIR"
  CERT_NAME=$(basename "$CERT_DIR")

  # ── Nginx config ──────────────────────────────────────────────────────────
  section "Configuring nginx"

  NGINX_CONF="/etc/nginx/sites-available/certvault"
  sudo tee "$NGINX_CONF" > /dev/null << NGINXEOF
# CertVault nginx config — managed by certvault.sh

server {
    listen 80;
    server_name ${CV_DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl;
    server_name ${CV_DOMAIN};

    ssl_certificate     ${CERT_DIR}/fullchain.pem;
    ssl_certificate_key ${CERT_DIR}/privkey.pem;
    ssl_trusted_certificate ${CERT_DIR}/chain.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:${CV_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 120;
        proxy_connect_timeout 10;
    }
}
NGINXEOF

  sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/certvault
  if [ -f /etc/nginx/sites-enabled/default ]; then
    warn "Removing nginx default site to avoid port 80 conflict"
    sudo rm -f /etc/nginx/sites-enabled/default
  fi

  info "Testing nginx config..."
  if sudo nginx -t 2>&1 | grep -q "successful"; then
    ok "Nginx config is valid"
  else
    sudo nginx -t
    die "Nginx config test failed — check the output above"
  fi

  sudo systemctl enable nginx --quiet
  sudo systemctl reload nginx
  ok "Nginx reloaded"

  # ── Auto-renew cron ───────────────────────────────────────────────────────
  section "Installing auto-renewal cron"

  RENEW_SCRIPT="$SCRIPT_DIR/renew-cert.sh"
  cat > "$RENEW_SCRIPT" << RENEWEOF
#!/bin/bash
# Auto-generated by certvault.sh — do not edit manually
/usr/bin/certbot renew \
  --cert-name ${CERT_NAME} \
  --dns-cloudflare \
  --dns-cloudflare-credentials ${CF_INI} \
  --quiet
/usr/bin/systemctl reload nginx
RENEWEOF
  chmod +x "$RENEW_SCRIPT"

  CRON_FILE="/etc/cron.d/certvault-renew"
  echo "0 3 * * * root $RENEW_SCRIPT >> /var/log/certvault-renew.log 2>&1" \
    | sudo tee "$CRON_FILE" > /dev/null
  ok "Auto-renew cron installed at $CRON_FILE (runs daily 03:00)"

  # ── Save config ───────────────────────────────────────────────────────────
  cat > "$HTTPS_CONF" << EOF
CV_DOMAIN=${CV_DOMAIN}
CV_EMAIL=${CV_EMAIL}
CV_PORT=${CV_PORT}
CV_CERT_DIR=${CERT_DIR}
CV_CERT_NAME=${CERT_NAME}
CV_NGINX_CONF=${NGINX_CONF}
CV_CF_INI=${CF_INI}
EOF
  ok "HTTPS config saved to $HTTPS_CONF"

  # ── Restart CertVault ─────────────────────────────────────────────────────
  section "Restarting CertVault"
  cmd_stop 2>/dev/null || true
  sleep 1
  cmd_start

  echo ""
  echo -e "  ${GREEN}${BOLD}╔══════════════════════════════════════════════╗${NC}"
  echo -e "  ${GREEN}${BOLD}║   ✅  HTTPS setup complete!                  ║${NC}"
  echo -e "  ${GREEN}${BOLD}╚══════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  ${BOLD}URL:${NC}        ${CYAN}https://$CV_DOMAIN${NC}"
  echo -e "  ${BOLD}Cert dir:${NC}   $CERT_DIR"
  echo -e "  ${BOLD}Nginx conf:${NC} $NGINX_CONF"
  echo -e "  ${BOLD}Auto-renew:${NC} $CRON_FILE (daily 03:00)"
  echo ""
  echo -e "  Useful commands:"
  echo -e "    ${CYAN}./certvault.sh https-status${NC}   — check cert & nginx"
  echo -e "    ${CYAN}./certvault.sh https-renew${NC}    — force certificate renewal"
  echo -e "    ${CYAN}./certvault.sh restart${NC}        — restart Flask"
  echo ""
}

# ─── HTTPS Renew (manual) ─────────────────────────────────────────────────────
cmd_https_renew() {
  [ -f "$HTTPS_CONF" ] || die "No HTTPS config found. Run: ./certvault.sh https-setup"
  # shellcheck disable=SC1090
  source "$HTTPS_CONF"
  section "Renewing certificate for $CV_DOMAIN"

  # Re-detect cert dir in case it moved (always with sudo)
  local cert_dir
  cert_dir=$(_find_cert_dir "$CV_DOMAIN" "${CV_CERT_NAME:-}") \
    || die "Cannot find certificate — run: sudo certbot certificates"

  local cert_name
  cert_name=$(basename "$cert_dir")

  sudo certbot renew \
    --cert-name "$cert_name" \
    --dns-cloudflare \
    --dns-cloudflare-credentials "$CV_CF_INI" \
    --quiet

  sudo systemctl reload nginx
  ok "Certificate renewed and nginx reloaded"
  cmd_https_status
}

# ─── HTTPS Status ─────────────────────────────────────────────────────────────
cmd_https_status() {
  [ -f "$HTTPS_CONF" ] || { warn "HTTPS not configured. Run: ./certvault.sh https-setup"; return; }
  # shellcheck disable=SC1090
  source "$HTTPS_CONF"

  section "HTTPS Status"
  echo ""
  echo -e "  ${BOLD}Domain:${NC}  $CV_DOMAIN"

  # Re-detect cert dir with sudo in case saved path is stale
  local cert_dir
  if cert_dir=$(_find_cert_dir "$CV_DOMAIN" "${CV_CERT_NAME:-}" 2>/dev/null); then
    echo -e "  ${BOLD}Cert:${NC}    $cert_dir"
    # Update saved path if it changed
    if [ "$cert_dir" != "$CV_CERT_DIR" ]; then
      sed -i "s|CV_CERT_DIR=.*|CV_CERT_DIR=${cert_dir}|" "$HTTPS_CONF"
      sed -i "s|CV_CERT_NAME=.*|CV_CERT_NAME=$(basename "$cert_dir")|" "$HTTPS_CONF"
    fi
  else
    err_msg "Certificate not found in /etc/letsencrypt/live"
    echo "  Run: sudo certbot certificates"
    cert_dir=""
  fi
  echo ""

  # Certificate expiry — read via sudo since dir is root-owned
  if [ -n "$cert_dir" ]; then
    local cert_file="$cert_dir/cert.pem"
    local expiry
    expiry=$(sudo openssl x509 -noout -enddate -in "$cert_file" 2>/dev/null | cut -d= -f2) || true
    if [ -n "$expiry" ]; then
      local epoch_exp days
      epoch_exp=$(date -d "$expiry" +%s 2>/dev/null) || epoch_exp=""
      if [ -n "$epoch_exp" ]; then
        days=$(( (epoch_exp - $(date +%s)) / 86400 ))
        if   [ "$days" -gt 14 ]; then ok "Certificate valid — expires $expiry (${days}d)"
        elif [ "$days" -gt 0  ]; then warn "Certificate expiring soon — $expiry (${days}d)"
        else                          err_msg "Certificate EXPIRED — $expiry"
        fi
      else
        warn "Could not parse expiry date: $expiry"
      fi
    else
      err_msg "Could not read certificate (try: sudo openssl x509 -noout -enddate -in $cert_file)"
    fi
  fi

  # Nginx config validity
  if sudo nginx -t > /dev/null 2>&1; then
    ok "Nginx config valid"
  else
    err_msg "Nginx config has errors — run: sudo nginx -t"
  fi

  # Nginx running
  if systemctl is-active --quiet nginx; then
    ok "Nginx is running"
  else
    err_msg "Nginx is NOT running — run: sudo systemctl start nginx"
  fi

  # Flask
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    ok "CertVault Flask is running (PID $(cat "$PID_FILE"), port $CV_PORT)"
  else
    warn "CertVault Flask is not running — run: ./certvault.sh start"
  fi
  echo ""
}

# ─── Systemd ──────────────────────────────────────────────────────────────────
cmd_systemd() {
  section "Installing systemd service"
  local user; user=$(whoami)

  local bind_host="0.0.0.0"
  local bind_port="$PORT"
  if [ -f "$HTTPS_CONF" ]; then
    # shellcheck disable=SC1090
    source "$HTTPS_CONF"
    bind_host="127.0.0.1"
    bind_port="$CV_PORT"
  fi

  sudo tee /etc/systemd/system/certvault.service > /dev/null << EOF
[Unit]
Description=CertVault Certificate Management System
After=network.target

[Service]
Type=simple
User=${user}
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${VENV_DIR}/bin/python ${SCRIPT_DIR}/app.py
Restart=on-failure
RestartSec=5
Environment="PORT=${bind_port}"
Environment="FLASK_HOST=${bind_host}"

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable certvault --quiet
  ok "Systemd service installed"
  echo ""
  echo "  sudo systemctl start certvault"
  echo "  sudo systemctl status certvault"
  echo "  journalctl -u certvault -f"
}

# ─── Help ─────────────────────────────────────────────────────────────────────
cmd_help() {
  banner
  echo -e "  ${BOLD}Usage:${NC} ./certvault.sh <command>"
  echo ""
  echo -e "  ${BOLD}${YELLOW}App Commands${NC}"
  echo "  install         Install Python dependencies"
  echo "  start           Start in background"
  echo "  stop            Stop background process"
  echo "  restart         Restart the server"
  echo "  status          Check if running"
  echo "  run             Run in foreground (Ctrl+C to stop)"
  echo "  logs            Tail the log file"
  echo "  systemd         Install as systemd service"
  echo ""
  echo -e "  ${BOLD}${YELLOW}HTTPS Commands${NC}"
  echo "  https-setup     Set up HTTPS (interactive — prompts for domain, email, CF token)"
  echo "  https-renew     Manually renew the TLS certificate"
  echo "  https-status    Show certificate expiry and nginx status"
  echo ""
  echo -e "  ${BOLD}${YELLOW}Environment${NC}"
  echo "  PORT            Internal Flask port (default: 5000)"
  echo ""
  echo -e "  ${BOLD}${YELLOW}HTTPS Requirements${NC}"
  echo "  - Domain pointing to this server's public IP"
  echo "  - Cloudflare managing DNS for the domain"
  echo "  - Cloudflare API token: Zone:Read + DNS:Edit"
  echo "  - sudo access (for nginx/certbot)"
  echo "  - nginx + certbot installed automatically by https-setup"
  echo ""
  echo -e "  ${BOLD}${YELLOW}Quick start:${NC}"
  echo "    ./certvault.sh install"
  echo "    ./certvault.sh start             # HTTP on :5000"
  echo "    ./certvault.sh https-setup       # then: HTTPS on :443"
}

# ─── Entry point ──────────────────────────────────────────────────────────────
case "${1:-help}" in
  install)          cmd_install ;;
  start)            cmd_start ;;
  stop)             cmd_stop ;;
  restart)          cmd_restart ;;
  status)           cmd_status ;;
  run)              cmd_foreground ;;
  logs)             cmd_logs ;;
  systemd)          cmd_systemd ;;
  https-setup)      cmd_https_setup ;;
  https-renew)      cmd_https_renew ;;
  https-status)     cmd_https_status ;;
  help|--help|-h|*) cmd_help ;;
esac
