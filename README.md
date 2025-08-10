# WebCheck
# Laravel Web App Security Recon & Baseline Testing (Kali Linux)

This README documents a **practical, low‑noise** workflow to recon and lightly test a Laravel web app from Kali Linux. It’s built to catch the most common misconfigurations and exposures (e.g., `.env`, Debugbar, Ignition, Telescope/Horizon) and to produce **actionable reports** you can hand to engineering.

> **Scope & Ethics**
> - Only test assets you own or have explicit written authorization for.
> - Keep scans conservative: avoid brute‑force, high‑risk payloads, or DoS‑like behavior.
> - Default target in examples: `a.com`. Replace with your domain.

---

## 0) Prerequisites

Kali usually ships most tools, but confirm/install if needed:

```bash
sudo apt update
sudo apt install -y whatweb wafw00f nmap nikto nuclei feroxbuster httpx
```

TLS tester (if missing on your box):
```bash
# Optional if not already available
git clone https://github.com/drwetter/testssl.sh.git ~/tools/testssl.sh
sudo ln -sf ~/tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
```

Subdomain & URL helpers (optional but useful):
```bash
# httpx is already installed above
# gau (GetAllURLs) and anew (dedupe) - optional
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/anew@latest
# Ensure $GOPATH/bin is in PATH, e.g.:
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc && source ~/.bashrc
```

OWASP ZAP (GUI) is preinstalled on Kali; if not:
```bash
sudo apt install -y zaproxy
```

---

## 1) Environment & Workspace

```bash
export DOMAIN="a.com"           # <- change to your domain
export TARGET="https://$DOMAIN"
mkdir -p ~/recon/$DOMAIN && cd ~/recon/$DOMAIN
```

---

## 2) Fingerprinting, WAF, and TLS/Headers

```bash
whatweb -v $TARGET
wafw00f $TARGET
nmap -Pn -p 80,443 --script http-security-headers,ssl-enum-ciphers $DOMAIN
testssl.sh -U --sneaky $DOMAIN
```

**What to look for**
- Missing HSTS / CSP / X-Frame-Options / X-Content-Type-Options ⇒ server hardening needed.
- Weak ciphers / outdated TLS ⇒ upgrade TLS config.

---

## 3) Subdomain & Service Discovery

```bash
amass enum -d $DOMAIN -o subs.txt
httpx -l subs.txt -ports 80,443,8080,8443 -status-code -title -server -o live-hosts.txt
```

**Why this matters**
- Admin panels or staging services sometimes leak on subdomains.

---

## 4) Content Discovery (Laravel-aware)

```bash
feroxbuster -u $TARGET -k   -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt   -x php,js,css,zip,sql,env,log,txt -o ferox.txt
```

Check common Laravel-sensitive paths quickly:

```bash
for p in /.env /storage/logs/laravel.log /vendor/composer/installed.json /composer.json /.git/HEAD /_debugbar /_ignition/execute-solution /telescope /horizon /.env.example ; do
  echo ">>> $p"; curl -k -s -I "$TARGET$p" | head -n 1
done
```

**Any 200/302 here is a red flag** (especially `.env`, Debugbar, Ignition, Telescope/Horizon).

---

## 5) Nuclei: PHP/Laravel Misconfig & Exposure

```bash
nuclei -u $TARGET   -tags "php,laravel,misconfig,exposure"   -severity low,medium,high,critical   -o nuclei.txt
```

Nuclei templates commonly catch:
- `.env` exposures
- Debugbar / Ignition (CVE‑2021‑3129 if debug+Ignition)
- Telescope / Horizon panels
- Common misconfigurations

> **Note:** If an Ignition RCE path is found, prioritize remediation immediately.

---

## 6) Nikto: Web Server Misconfig Snapshot

```bash
nikto -h $TARGET -ssl -o nikto.txt
```

Catches default files, backups, dangerous methods, etc.

---

## 7) Parameter Harvesting & Light SQL Injection Testing (Optional)

Aggregate URLs and parameters (multiple sources improve coverage):

```bash
# Gather URLs (from prior outputs and historical sources if gau is installed)
cat ferox.txt live-hosts.txt 2>/dev/null | grep -Eo 'https?://[^ ]+' | sort -u > urls.txt
gau --subs $DOMAIN | tee -a urls.txt         # optional
cat urls.txt | grep '?' | anew params.txt    # requires anew (optional)
```

**Light SQLMap run (conservative):**
```bash
sqlmap -m params.txt --batch --random-agent --level=2 --risk=1 --threads=2 --dbms=mysql
```
Start with specific, meaningful targets; don’t blast the whole site.

---

## 8) OWASP ZAP Baseline (GUI)

1. Launch ZAP → *Quick Scan* on `$TARGET`.
2. Generate an HTML report (baseline/passive first; avoid aggressive active scans initially).
3. Triage the alerts by confidence and risk.

---

## 9) Manual App Checks (High Value, Low Noise)

- **Auth/Session/CSRF**
  - All POST endpoints require CSRF tokens.
  - Cookies set `Secure`, `HttpOnly`, `SameSite=Lax|Strict`.
- **Rate limiting**
  - Login/OTP/Password reset throttle (e.g., 5–10 failed attempts ⇒ delay/lockout).
- **File Uploads**
  - Enforce allowlist; store under non-executable paths (e.g., `/storage`); verify content-type and magic bytes.
- **IDOR/Access Control**
  - Change resource IDs and confirm robust authorization checks.
- **Debug/Logs**
  - No debug info in responses; log level appropriate; no sensitive logs exposed via web.

---

## 10) Hardening Checklist

**Laravel / App**
- `APP_ENV=production` and `APP_DEBUG=false`
- Rotate a strong `APP_KEY`; invalidate old sessions as needed
- Lock down `/telescope` and `/horizon` behind auth/VPN/IP allowlists
- Remove/disable Debugbar in production
- Keep framework & packages up to date (update in dev; deploy via CI/CD)
- Move public uploads outside webroot or disable execution in upload paths
- Run: `php artisan config:cache route:cache view:cache` in CI

**Web Server / Headers**
- HSTS (with preload after validation), CSP (start simple), X-Frame-Options (SAMEORIGIN), X-Content-Type-Options (nosniff),
  Referrer-Policy, Permissions-Policy
- Deny dotfiles and directory listing
  - **Nginx**
    ```nginx
    location ~ /\.(?!well-known).* { deny all; }
    autoindex off;
    ```
  - **Apache**
    ```apache
    RedirectMatch 404 /\..*
    Options -Indexes
    ```

---

## 11) Quick One-Command Audit

Use the helper script to run a minimal baseline and collect outputs into a timestamped folder.

### Script: `quick_laravel_check.sh`

```bash
#!/usr/bin/env bash
set -e
DOMAIN="${1:-a.com}"
TARGET="https://$DOMAIN"
WD="$HOME/recon/$DOMAIN/quick-$(date +%F-%H%M)"
mkdir -p "$WD"; cd "$WD"
echo "[*] Target: $TARGET"

echo "[*] WhatWeb / WAF / Headers"
whatweb -v $TARGET | tee whatweb.txt
wafw00f $TARGET | tee waf.txt
nmap -Pn -p 80,443 --script http-security-headers,ssl-enum-ciphers $DOMAIN | tee nmap.txt

echo "[*] Sensitive Laravel endpoints"
ENDPOINTS=(/.env /storage/logs/laravel.log /vendor/composer/installed.json /composer.json /.git/HEAD /_debugbar /_ignition/execute-solution /telescope /horizon)
for p in "${ENDPOINTS[@]}"; do
  code=$(curl -k -s -o /dev/null -w "%{http_code}" "$TARGET$p")
  echo "$code  $p" | tee -a laravel_sensitive.txt
done

echo "[*] Nuclei (misconfig/exposures/php)"
nuclei -u $TARGET -tags "php,laravel,misconfig,exposure" -severity low,medium,high,critical -o nuclei.txt || true

echo "[*] Nikto"
nikto -h $TARGET -ssl -o nikto.txt

echo "[*] Dir brute (feroxbuster)"
feroxbuster -u $TARGET -k -x php,js,css,zip,sql,env,log,txt -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o ferox.txt || true

echo "[*] Done. Reports in $WD"
```

**Run it:**
```bash
chmod +x quick_laravel_check.sh
./quick_laravel_check.sh yourdomain.com
```

Outputs will be under: `~/recon/<domain>/quick-YYYY-MM-DD-HHMM/`

---

## 12) Reports & Next Steps

1. **Prioritize criticals** (e.g., `.env` exposed, Ignition debug endpoints, open admin panels).
2. Apply hardening (Laravel + server headers) from the checklist.
3. Re-run the quick script and confirm deltas are resolved.
4. Consider a follow-up authenticated test for authorization/IDOR and business-logic issues.

---

## 13) Clean Up

```bash
# Remove recon folder if needed (irreversible)
rm -rf ~/recon/$DOMAIN
```

---

## Attribution / Rights

**x:m7mdatd Mohammed Almawi**

This workflow is provided “as-is” without warranty of any kind. Use responsibly and within the law.
