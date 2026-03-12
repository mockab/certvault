> **Vibe Coded**

# 🔐 CertVault — Certificate Management System

A self-hosted web application for managing SSL/TLS certificates. Stores certs, tracks expiry, issues new certificates via Let's Encrypt, and serves itself over HTTPS.

---

## Features

### 📜 Certificate Management
- **Store certificates** with private keys, chains, CSRs, and arbitrary extra files
- **Auto-parse cert metadata** — expiry dates, SANs, issuer, subject, key size, algorithm, CA flag
- **File versioning** — mark an upload as a renewal to archive the old files and activate the new ones
- **Custom tags** and **accent colours** per certificate for easy visual organisation
- **Notes** — free-form text notes per certificate entry
- **Expiry dashboard** — cards colour-coded healthy / warning (≤30d) / critical (≤7d) / expired
- **Search, sort, and filter** by name, domain, tag, or expiry status

### 🔐 Authentication & Security
- **User login** — username + password with PBKDF2-HMAC-SHA256 hashing (260 000 iterations)
- **First-run setup** — no default credentials; you create the admin account on first visit
- **TOTP two-factor authentication** — scan a QR code with Google Authenticator, Authy, 1Password, etc.
- **Change password** from the Account page at any time
- **Session management** — sessions expire after 7 days; all API endpoints require authentication
- **Brute-force delay** — failed logins are rate-limited with a 0.5 s server-side delay

### 📍 Locations Tracking
- Record every place a certificate is deployed (nginx on prod-web-01, AWS ALB, etc.)
- Track the **responsible person**, **contact info**, and step-by-step **replacement procedure** per location
- Multiple locations per certificate

### 🔔 Slack Notifications
- Per-certificate or global Slack webhook URLs
- Configurable day thresholds (e.g. 60, 30, 14, 7, 3, 1 days before expiry)
- CertVault checks hourly and sends **one notification per day per threshold** to avoid spam
- Test webhook button built into the UI
- Manual "run check now" trigger from the Notifications view

### ⚡ Let's Encrypt via Cloudflare DNS
- Issue or renew certificates from inside the UI (Let's Encrypt view) **or** via `certvault.sh https-setup`
- Uses **Cloudflare DNS-01 challenge** — no port 80/443 required on the server for issuance
- Automatically imports issued files into CertVault and parses the certificate info
- Background job with live status polling and log viewer
- Requires a Cloudflare API token with `Zone:Read` + `DNS:Edit` permissions

### 📦 Export
| Format | Description |
|--------|-------------|
| ZIP Archive | All active files bundled in a ZIP |
| PEM Bundle | Certificate + chain + key concatenated into one `.pem` |
| Certificate Only | The cert `.pem` alone |
| Chain / Intermediate | The chain `.pem` alone |
| Private Key Only | The key `.pem` alone |
| PFX / PKCS#12 | Password-protected single file (requires `openssl`) |
| DER | Binary DER-encoded certificate |

**PFX password generator** — built-in cryptographically secure password generator with toggles for uppercase, lowercase, digits, and special characters, plus a length slider (8–64 chars) and one-click copy.

### 🌐 HTTPS / Production Setup
- `./certvault.sh https-setup` — interactive wizard that:
  - Obtains a Let's Encrypt certificate via Cloudflare DNS
  - Installs and configures **nginx** as a TLS reverse proxy
  - Redirects HTTP → HTTPS automatically
  - Locks Flask to `127.0.0.1` (not directly reachable from outside)
  - Installs a **daily cron job** for automatic renewal
- Modern TLS config: TLS 1.2/1.3 only, HSTS, OCSP stapling, security headers
- `./certvault.sh https-status` — shows certificate expiry and nginx health at a glance
- `./certvault.sh https-renew` — force-renew the certificate manually

---

## Quick Start

### Requirements
- Ubuntu 22/24 or any Debian-based Linux
- Python 3.8+, pip, venv
- `openssl` in PATH (pre-installed on most systems)
- `sudo` access (only needed for `https-setup` and `systemd`)

### Install & Run (HTTP)

```bash
chmod +x certvault.sh
./certvault.sh install   # creates venv, installs flask + cryptography
./certvault.sh start     # starts in background on http://localhost:5000
```

Open `http://<your-server>:5000` — you'll be prompted to create your admin account.

### Set Up HTTPS (recommended for production)

```bash
./certvault.sh https-setup
```

You will be prompted for:
1. **Domain name** — e.g. `certs.example.com` (must point to this server's IP)
2. **Email** — for Let's Encrypt expiry notices
3. **Cloudflare API token** — create at https://dash.cloudflare.com/profile/api-tokens  
   Required permissions: `Zone → Zone (Read)` + `Zone → DNS (Edit)`
4. **Internal Flask port** — defaults to 5000

After setup, CertVault is available at `https://your-domain.com`. Flask is locked to localhost only and nginx handles all external traffic.

---

## All Commands

### App

```bash
./certvault.sh install        # Install Python dependencies into venv
./certvault.sh start          # Start in background
./certvault.sh stop           # Stop background process
./certvault.sh restart        # Restart
./certvault.sh status         # Check if running + print URL
./certvault.sh run            # Start in foreground (Ctrl+C to stop)
./certvault.sh logs           # Tail the log file
./certvault.sh systemd        # Install as systemd service (auto-start on boot)
```

### HTTPS

```bash
./certvault.sh https-setup    # Full interactive HTTPS setup
./certvault.sh https-renew    # Force certificate renewal + reload nginx
./certvault.sh https-status   # Show cert expiry, nginx status, Flask status
```

### Custom Port

```bash
PORT=8080 ./certvault.sh start
```

After `https-setup` the port is saved in `.https.conf` and used automatically — no need to specify it again.

---

## Systemd (Auto-start on Boot)

```bash
./certvault.sh systemd
sudo systemctl start certvault
sudo systemctl status certvault
journalctl -u certvault -f
```

The systemd unit automatically uses the correct bind address (localhost if HTTPS is configured, `0.0.0.0` otherwise).

---

## Workflow: Adding a Certificate

1. Click **+ Add Certificate** in the sidebar
2. Enter a name, domain/CN, optional tags, notes, accent colour, and Slack webhook
3. Open the **Files** tab → click **Upload** and add your `.pem`, `.crt`, `.key`, `.chain`, etc.
4. CertVault parses the certificate automatically and populates expiry, SANs, issuer, and key info
5. Use the **Locations** tab to record every server/service where the cert is deployed
6. Use the **Export** tab to download in any format when you need to deploy a renewal

---

## Workflow: Issuing a Certificate (Let's Encrypt)

### Via the UI
1. Go to **⚡ Let's Encrypt** in the sidebar
2. Enter the domain, optional extra SANs, email, and Cloudflare API token
3. Optionally link to an existing CertVault entry (files are auto-imported on success)
4. Click **Issue Certificate** — a background job runs and the log updates live

### Via the command line (also sets up HTTPS)
```bash
./certvault.sh https-setup
```

---

## Workflow: Enabling MFA

1. Go to **👤 Account & Security** in the sidebar
2. Click **Enable MFA →**
3. Scan the QR code with your authenticator app (or enter the secret key manually)
4. Enter the 6-digit code from your app to confirm
5. On your next login you'll be prompted for the code after your password

To disable MFA, enter your current authenticator code in the **Disable MFA** section.

---

## File Structure

```
certvault/
├── app.py                  # Flask backend (all API routes)
├── certvault.sh            # Management script (start/stop/https/systemd)
├── certvault.db            # SQLite database (auto-created on first run)
├── templates/
│   ├── index.html          # Main web UI (single-page app)
│   └── login.html          # Login / first-run setup page
├── certs_store/            # Certificate files stored here (one folder per cert)
├── exports/                # Temporary export files (cleaned up automatically)
├── renew-cert.sh           # Auto-generated by https-setup; runs certbot renew
├── .https.conf             # Auto-generated; stores domain, port, paths
├── .cf-credentials.ini     # Cloudflare API token (chmod 600, generated by https-setup)
└── venv/                   # Python virtualenv (created by install)
```

---

## Security Notes

- **Private keys are stored on disk** — restrict file system permissions on the `certs_store/` directory
- After `https-setup`, Flask binds to `127.0.0.1` only; nginx is the only public entry point
- The Cloudflare API token in `.cf-credentials.ini` is stored with `chmod 600`
- TOTP MFA is strongly recommended for any internet-facing deployment
- All sessions are server-side; clearing cookies or restarting Flask invalidates them
- The `SECRET_KEY` for Flask sessions is random per-process unless set via the `SECRET_KEY` environment variable — set a persistent one if you want sessions to survive restarts:

```bash
# Generate a key
python3 -c "import secrets; print(secrets.token_hex(32))"

# Add to your shell / systemd unit
export SECRET_KEY=<your-key>
./certvault.sh start
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `flask` | Web framework |
| `cryptography` | Certificate parsing (X.509) |
| `certbot` | Let's Encrypt client (installed by `https-setup`) |
| `python3-certbot-dns-cloudflare` | Cloudflare DNS plugin for certbot (installed by `https-setup`) |
| `nginx` | TLS reverse proxy (installed by `https-setup`) |
| `openssl` | PFX/DER export (system package, usually pre-installed) |

All Python dependencies are isolated in `venv/`. No system Python packages are modified.

---

## Troubleshooting

**App won't start**  
Check `./certvault.sh logs` for Python errors. Make sure the venv exists (`./certvault.sh install`).

**Certificates page is empty after adding a cert**  
Hard-refresh the browser (`Ctrl+Shift+R`) to clear any cached JS.

**TOTP code is always invalid**  
Ensure your device's clock is accurate (TOTP is time-based). Try syncing NTP: `sudo timedatectl set-ntp true`.

**`https-setup` fails at certbot**  
- Verify your Cloudflare API token has `Zone:Read` + `DNS:Edit` on the correct zone
- Ensure the domain's DNS is managed by Cloudflare (not just proxied)
- Check certbot output in the setup log for the specific error

**nginx returns 502 after https-setup**  
Flask isn't running. Start it: `./certvault.sh start`

**Sessions don't persist across Flask restarts**  
Set a persistent `SECRET_KEY` environment variable (see Security Notes above).
