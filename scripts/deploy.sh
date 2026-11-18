#!/usr/bin/env bash
# One-step Socratex server deployment for Debian/Ubuntu (systemd, x64/arm64).
#
#   sudo bash deploy.sh --domain proxy.example.com [--email you@example.com]
#   sudo bash deploy.sh --show                # print client links again
#   sudo bash deploy.sh --uninstall [--purge] # remove (purge also deletes credentials)
#
# Re-running the install updates the code and keeps existing credentials.
# See `sudo bash deploy.sh --help` for every option.
set -Eeuo pipefail
umask 022

REPO_URL_DEFAULT="https://github.com/qiangweihewu/socratex-hardened.git"
BASE=/opt/socratex
APP="$BASE/app"
NODE_DIR="$BASE/node"
ETC=/etc/socratex
ENV_FILE="$ETC/socratex.env"
TLS_DIR="$ETC/tls"
LINKS_FILE="$ETC/client-links.txt"
STATE=/var/lib/socratex
SERVICE=socratex
UNIT="/etc/systemd/system/$SERVICE.service"
HOOK=/etc/letsencrypt/renewal-hooks/deploy/socratex.sh
SYSCTL_FILE=/etc/sysctl.d/90-socratex.conf
HEALTH_URL="https://1.1.1.1/cdn-cgi/trace"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO: $BASH_COMMAND"' ERR

usage() {
    cat <<'EOF'
Usage: sudo bash deploy.sh --domain DOMAIN [options]
       sudo bash deploy.sh --show | --uninstall [--purge]

Install / update:
  --domain DOMAIN       Public hostname whose DNS A/AAAA record points here (required on first install)
  --email EMAIL         Let's Encrypt account e-mail (recommended for expiry notices)
  --port PORT           Proxy port (default 443)
  --user NAME           Proxy username (default: kept, else random)
  --password PASS       Proxy password, 12-128 chars of [A-Za-z0-9._~-] (default: kept, else random)
  --stealth             Probe resistance: unauthenticated requests get 404 instead of 407
  --no-stealth          Turn probe resistance off again
  --cert-file PATH      Use an existing certificate chain instead of certbot (you renew it)
  --key-file PATH       Private key for --cert-file
  --tune-network        Enable BBR and larger TCP buffers (/etc/sysctl.d/90-socratex.conf)
  --ref REF             Git branch or tag to deploy (default: main, or the one already deployed)
  --repo URL            Git repository (default: qiangweihewu/socratex-hardened)
  --name NAME           Profile name shown in client links (default: socratex)

Other:
  --show                Print the client configuration links again
  --uninstall           Stop and remove the service and code (keeps credentials and certificates)
  --purge               With --uninstall: also delete credentials, state, sysctl file and service user
EOF
}

# ---------- arguments ----------
ACTION=install DOMAIN="" EMAIL="" PORT="" P_USER="" P_PASS="" STEALTH="" CERT_FILE="" KEY_FILE=""
TUNE=0 REF="" REPO_URL="" NAME="" PURGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --domain) DOMAIN="${2:-}"; shift ;;
        --email) EMAIL="${2:-}"; shift ;;
        --port) PORT="${2:-}"; shift ;;
        --user) P_USER="${2:-}"; shift ;;
        --password) P_PASS="${2:-}"; shift ;;
        --stealth) STEALTH=1 ;;
        --no-stealth) STEALTH=0 ;;
        --cert-file) CERT_FILE="${2:-}"; shift ;;
        --key-file) KEY_FILE="${2:-}"; shift ;;
        --tune-network) TUNE=1 ;;
        --ref) REF="${2:-}"; shift ;;
        --repo) REPO_URL="${2:-}"; shift ;;
        --name) NAME="${2:-}"; shift ;;
        --show) ACTION=show ;;
        --uninstall) ACTION=uninstall ;;
        --purge) PURGE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
    shift
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash deploy.sh ...)"
[ "$(uname -s)" = Linux ] || die "Linux only"

# Settings persisted from a previous run (root-only file written by this script).
load_env() {
    [ -f "$ENV_FILE" ] || return 0
    local key value
    while IFS='=' read -r key value; do
        case "$key" in
            SOCRATEX_USER) OLD_USER="$value" ;; SOCRATEX_PASSWORD) OLD_PASS="$value" ;;
            SOCRATEX_DOMAIN) OLD_DOMAIN="$value" ;; SOCRATEX_PORT) OLD_PORT="$value" ;;
            SOCRATEX_SECRET_DOMAIN) OLD_SECRET="$value" ;; DEPLOY_STEALTH) OLD_STEALTH="$value" ;;
            DEPLOY_REF) OLD_REF="$value" ;; DEPLOY_REPO) OLD_REPO="$value" ;;
            DEPLOY_NAME) OLD_NAME="$value" ;; DEPLOY_CERT) OLD_CERT="$value" ;;
        esac
    done < "$ENV_FILE"
}
OLD_USER="" OLD_PASS="" OLD_DOMAIN="" OLD_PORT="" OLD_SECRET="" OLD_STEALTH="" OLD_REF="" OLD_REPO="" OLD_NAME="" OLD_CERT=""
load_env

# ---------- client links ----------
show_links() {
    [ -f "$ENV_FILE" ] || die "not installed yet ($ENV_FILE missing)"
    OLD_USER="" OLD_PASS="" OLD_DOMAIN="" OLD_PORT="" OLD_SECRET="" OLD_NAME=""
    load_env
    local u="$OLD_USER" p="$OLD_PASS" d="$OLD_DOMAIN" port="$OLD_PORT" name="${OLD_NAME:-socratex}"
    # Credentials only use URL-unreserved characters, so no encoding is needed.
    {
        echo "================ Socratex client configuration ================"
        echo
        echo "Server: $d   Port: $port   Username: $u   Password: $p"
        echo
        echo "[NaïveProxy link] NekoBox / husi / Exclave / v2rayN (import from clipboard):"
        echo "naive+https://$u:$p@$d:$port#$name"
        echo
        echo "[Standard HTTPS proxy URL] naive CLI config.json \"proxy\", curl --proxy, other HTTPS-proxy clients:"
        echo "https://$u:$p@$d:$port"
        echo
        echo "[Clash Meta / mihomo] add under proxies:"
        echo "  - name: $name"
        echo "    type: http"
        echo "    server: $d"
        echo "    port: $port"
        echo "    username: $u"
        echo "    password: $p"
        echo "    tls: true"
        echo "    sni: $d"
        echo
        echo "[Shadowrocket] import from clipboard (format Shadowrocket itself exports):"
        echo "https://$u:$p@$d:$port?peer=$d&method=auto&fingerprint=Safari26_3#$name"
        echo "  Keep HTTP2 off in the node's TLS settings: this server speaks HTTP/1.1."
        echo
        echo "[Test from any machine]"
        echo "curl -sS -o /dev/null -w '%{http_code}\\n' --proxy 'https://$u:$p@$d:$port' https://www.gstatic.com/generate_204"
        if [ -n "$OLD_SECRET" ]; then
            echo
            echo "[Stealth mode] clients must send credentials up front (naive clients and curl do)."
            echo "Browsers: with the proxy configured, open http://$OLD_SECRET/ once to get the login prompt."
        fi
        echo
        echo "Keep these credentials private. Show again: sudo bash deploy.sh --show"
        echo "================================================================"
    } | (umask 077; tee "$LINKS_FILE")
    if command -v qrencode >/dev/null 2>&1; then
        echo; echo "NaïveProxy link as QR code (scan with NekoBox / husi):"
        qrencode -t ANSIUTF8 "naive+https://$u:$p@$d:$port#$name"
    fi
}

# ---------- uninstall ----------
uninstall() {
    info "stopping and removing the $SERVICE service"
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f "$UNIT" "$HOOK"
    systemctl daemon-reload
    rm -rf "$BASE"
    if [ "$PURGE" -eq 1 ]; then
        info "purging credentials, state, sysctl tuning and the service user"
        rm -rf "$ETC" "$STATE"
        if [ -f "$SYSCTL_FILE" ]; then rm -f "$SYSCTL_FILE"; sysctl --system >/dev/null || true; fi
        id "$SERVICE" >/dev/null 2>&1 && userdel "$SERVICE" || true
        [ -n "$OLD_DOMAIN" ] && [ -d "/etc/letsencrypt/live/$OLD_DOMAIN" ] && \
            echo "The Let's Encrypt certificate is kept; remove it with: certbot delete --cert-name $OLD_DOMAIN"
    else
        echo "Credentials kept in $ETC (use --uninstall --purge to delete them)."
    fi
    info "done"
}

case "$ACTION" in
    show) show_links; exit 0 ;;
    uninstall) uninstall; exit 0 ;;
esac

# ---------- validate settings ----------
command -v systemctl >/dev/null || die "systemd is required"
command -v apt-get >/dev/null || die "only Debian/Ubuntu (apt) is supported by this script"
DOMAIN="${DOMAIN:-$OLD_DOMAIN}"
[ -n "$DOMAIN" ] || die "--domain is required"
[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]] || die "invalid domain: $DOMAIN"
DOMAIN="${DOMAIN,,}"
PORT="${PORT:-${OLD_PORT:-443}}"
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "invalid port: $PORT"
[ -z "$EMAIL" ] || [[ "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die "invalid e-mail: $EMAIL"
REF="${REF:-${OLD_REF:-main}}"
REPO_URL="${REPO_URL:-${OLD_REPO:-$REPO_URL_DEFAULT}}"
NAME="${NAME:-${OLD_NAME:-socratex}}"
[[ "$NAME" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || die "--name must be 1-32 chars of [A-Za-z0-9._-]"
random_alnum() { tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1" || true; }
P_USER="${P_USER:-${OLD_USER:-u$(random_alnum 7)}}"
P_PASS="${P_PASS:-${OLD_PASS:-$(random_alnum 32)}}"
[[ "$P_USER" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "--user must be 1-64 chars of [A-Za-z0-9._-]"
[[ "$P_PASS" =~ ^[A-Za-z0-9._~-]{12,128}$ ]] || die "--password must be 12-128 chars of [A-Za-z0-9._~-]"
STEALTH="${STEALTH:-${OLD_STEALTH:-0}}"
SECRET_DOMAIN=""
if [ "$STEALTH" = 1 ]; then SECRET_DOMAIN="${OLD_SECRET:-$(random_alnum 16 | tr 'A-Z' 'a-z').example}"; fi
if [ -n "$CERT_FILE$KEY_FILE" ]; then
    [ -r "$CERT_FILE" ] && [ -r "$KEY_FILE" ] || die "--cert-file and --key-file must both be readable files"
    CERT_MODE=custom
else
    CERT_MODE="${OLD_CERT:-certbot}"
    [ "$CERT_MODE" != custom ] || [ -s "$TLS_DIR/fullchain.pem" ] || die "previous install used custom certificates; pass --cert-file/--key-file again"
fi

case "$(uname -m)" in
    x86_64|amd64) NODE_ARCH=x64 ;;
    aarch64|arm64) NODE_ARCH=arm64 ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
esac

port_owner() { ss -ltnpH "sport = :$1" 2>/dev/null | awk 'NR == 1' || true; }
check_port_free() {
    local owner; owner="$(port_owner "$1")"
    [ -z "$owner" ] || [[ "$owner" == *'"node"'* && "$(systemctl is-active "$SERVICE" 2>/dev/null)" = active ]] \
        || die "port $1 is already in use: $owner"
}

# ---------- packages ----------
info "installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
PKGS=(ca-certificates curl git xz-utils iproute2 openssl qrencode)
[ "$CERT_MODE" = certbot ] && PKGS+=(certbot)
apt-get install -y -qq --no-install-recommends "${PKGS[@]}" >/dev/null

# ---------- preflight ----------
check_port_free "$PORT"
if [ "$CERT_MODE" = certbot ] && [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    owner="$(port_owner 80)"; [ -z "$owner" ] || die "certbot needs port 80 free for the HTTP-01 challenge, but it is used by: $owner (free it, or use --cert-file/--key-file)"
fi
resolved="$(getent ahosts "$DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ' || true)"
[ -n "$resolved" ] || die "$DOMAIN does not resolve; create its DNS record first"
local_ips="$(ip -o addr show | awk '{split($4, a, "/"); print a[1]}' | sort -u | tr '\n' ' ')"
match=0; for ip in $resolved; do [[ " $local_ips " == *" $ip "* ]] && match=1; done
[ "$match" = 1 ] || warn "$DOMAIN resolves to [$resolved] which is not on this machine's interfaces. Fine behind NAT / elastic IP, otherwise fix DNS."

# ---------- Node.js 22 ----------
node_ok() { "$1" -e 'process.exit(+process.versions.node.split(".")[0] >= 22 ? 0 : 1)' >/dev/null 2>&1; }
if [ -x "$NODE_DIR/bin/node" ] && node_ok "$NODE_DIR/bin/node"; then
    NODE="$NODE_DIR/bin/node"
elif command -v node >/dev/null && node_ok "$(command -v node)" && command -v npm >/dev/null; then
    NODE="$(command -v node)"
else
    info "installing Node.js 22 (official build, SHA-256 verified)"
    dist=https://nodejs.org/dist/latest-v22.x
    tmp="$(mktemp -d)"
    curl -fsSL "$dist/SHASUMS256.txt" -o "$tmp/SHASUMS256.txt"
    file="$(grep -oE "node-v22\.[0-9]+\.[0-9]+-linux-$NODE_ARCH\.tar\.xz" "$tmp/SHASUMS256.txt" | awk 'NR == 1' || true)"
    [ -n "$file" ] || die "no Node.js 22 build found for linux-$NODE_ARCH"
    curl -fsSL "$dist/$file" -o "$tmp/$file"
    (cd "$tmp" && grep " $file\$" SHASUMS256.txt | sha256sum -c --status) || die "Node.js checksum mismatch"
    rm -rf "$NODE_DIR"; mkdir -p "$NODE_DIR"
    tar -xJf "$tmp/$file" -C "$NODE_DIR" --strip-components=1
    rm -rf "$tmp"
    NODE="$NODE_DIR/bin/node"
fi
NPM="$(dirname "$NODE")/npm"
info "using Node.js $("$NODE" -v) at $NODE"

# ---------- code ----------
info "fetching $REPO_URL ($REF)"
mkdir -p "$BASE"
if [ -d "$APP/.git" ]; then
    git -C "$APP" remote set-url origin "$REPO_URL"
    git -C "$APP" fetch -q --depth 1 origin "$REF"
    git -C "$APP" checkout -q --force FETCH_HEAD
    git -C "$APP" clean -qfdx -e node_modules
else
    rm -rf "$APP"
    git clone -q --depth 1 --branch "$REF" "$REPO_URL" "$APP"
fi
COMMIT="$(git -C "$APP" rev-parse --short HEAD)"
(cd "$APP" && PATH="$(dirname "$NODE"):$PATH" NPM_CONFIG_UPDATE_NOTIFIER=false "$NPM" ci --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error)
"$NODE" --input-type=module -e "import('$APP/lib/padding.mjs')" >/dev/null 2>&1 \
    || warn "the deployed revision ($REF@$COMMIT) predates NaïveProxy padding support; naive links need the newer code"

# ---------- user, credentials ----------
id "$SERVICE" >/dev/null 2>&1 || useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin "$SERVICE"
install -d -m 700 -o "$SERVICE" -g "$SERVICE" "$STATE"
install -d -m 755 "$ETC"
install -d -m 750 -o root -g "$SERVICE" "$TLS_DIR"
EXTRA_ARGS=""; [ "$STEALTH" = 1 ] && EXTRA_ARGS="--stealth"
tmp_env="$(mktemp)"
cat > "$tmp_env" <<EOF
SOCRATEX_USER=$P_USER
SOCRATEX_PASSWORD=$P_PASS
SOCRATEX_DOMAIN=$DOMAIN
SOCRATEX_PORT=$PORT
SOCRATEX_SECRET_DOMAIN=$SECRET_DOMAIN
SOCRATEX_EXTRA_ARGS=$EXTRA_ARGS
DEPLOY_STEALTH=$STEALTH
DEPLOY_REF=$REF
DEPLOY_REPO=$REPO_URL
DEPLOY_NAME=$NAME
DEPLOY_CERT=$CERT_MODE
EOF
install -m 600 -o root -g root "$tmp_env" "$ENV_FILE"; rm -f "$tmp_env"

# ---------- certificate ----------
install_cert() { # $1 chain, $2 key
    install -m 640 -o root -g "$SERVICE" "$1" "$TLS_DIR/fullchain.pem"
    install -m 640 -o root -g "$SERVICE" "$2" "$TLS_DIR/privkey.pem"
}
if [ "$CERT_MODE" = custom ]; then
    [ -z "$CERT_FILE" ] || install_cert "$CERT_FILE" "$KEY_FILE"
    warn "custom certificate: you must renew it and re-run with --cert-file/--key-file (or copy into $TLS_DIR and restart $SERVICE)"
else
    if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
        info "requesting a Let's Encrypt certificate for $DOMAIN"
        args=(certonly --standalone --preferred-challenges http --non-interactive --agree-tos -d "$DOMAIN")
        if [ -n "$EMAIL" ]; then args+=(-m "$EMAIL"); else args+=(--register-unsafely-without-email); fi
        if certbot --help all 2>/dev/null | grep -- '--key-type' >/dev/null; then args+=(--key-type ecdsa); fi
        certbot "${args[@]}" || die "certbot failed: check that $DOMAIN points here and inbound TCP 80 is open (firewall / cloud security group)"
    fi
    mkdir -p "$(dirname "$HOOK")"
    cat > "$HOOK" <<EOF
#!/bin/sh
# Installed by socratex deploy.sh: copy renewed certificates and restart.
set -e
[ "\$RENEWED_LINEAGE" = "/etc/letsencrypt/live/$DOMAIN" ] || exit 0
install -m 640 -o root -g $SERVICE "\$RENEWED_LINEAGE/fullchain.pem" $TLS_DIR/fullchain.pem
install -m 640 -o root -g $SERVICE "\$RENEWED_LINEAGE/privkey.pem" $TLS_DIR/privkey.pem
systemctl restart $SERVICE
EOF
    chmod 755 "$HOOK"
    install_cert "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
fi
openssl x509 -noout -checkhost "$DOMAIN" -in "$TLS_DIR/fullchain.pem" 2>/dev/null | grep 'does match' >/dev/null \
    || die "the certificate in $TLS_DIR does not cover $DOMAIN"
openssl x509 -noout -checkend 604800 -in "$TLS_DIR/fullchain.pem" >/dev/null \
    || warn "the certificate expires within 7 days"

# ---------- optional network tuning ----------
if [ "$TUNE" = 1 ]; then
    info "applying network tuning ($SYSCTL_FILE)"
    modprobe tcp_bbr 2>/dev/null || true
    {
        echo "# Installed by socratex deploy.sh --tune-network"
        if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
            echo "net.core.default_qdisc = fq"; echo "net.ipv4.tcp_congestion_control = bbr"
        else
            echo "# bbr unavailable on this kernel"
        fi
        echo "net.core.rmem_max = 16777216"; echo "net.core.wmem_max = 16777216"
        echo "net.ipv4.tcp_rmem = 4096 87380 16777216"; echo "net.ipv4.tcp_wmem = 4096 65536 16777216"
        echo "net.core.somaxconn = 4096"; echo "net.ipv4.tcp_slow_start_after_idle = 0"
    } > "$SYSCTL_FILE"
    sysctl -q --system || warn "some sysctl settings were not applied"
fi

# ---------- systemd ----------
info "installing systemd service"
cat > "$UNIT" <<EOF
[Unit]
Description=Socratex HTTPS forward proxy
After=network-online.target
Wants=network-online.target

[Service]
User=$SERVICE
Group=$SERVICE
EnvironmentFile=$ENV_FILE
Environment=HOME=$STATE
WorkingDirectory=$APP
ExecStart=$NODE main.mjs --domain=\${SOCRATEX_DOMAIN} --port=\${SOCRATEX_PORT} --cert=$TLS_DIR/fullchain.pem --key=$TLS_DIR/privkey.pem \$SOCRATEX_EXTRA_ARGS
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$STATE
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable -q "$SERVICE"
systemctl restart "$SERVICE"

# ---------- firewall ----------
FW_PORTS=("$PORT/tcp"); [ "$CERT_MODE" = certbot ] && FW_PORTS+=(80/tcp)
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep 'Status: active' >/dev/null; then
    for fw_port in "${FW_PORTS[@]}"; do ufw allow "$fw_port" >/dev/null; done
    info "ufw: opened ${FW_PORTS[*]}"
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    for fw_port in "${FW_PORTS[@]}"; do firewall-cmd -q --permanent --add-port="$fw_port"; done
    firewall-cmd -q --reload; info "firewalld: opened ${FW_PORTS[*]}"
fi

# ---------- health check ----------
info "waiting for the proxy to start"
for _ in $(seq 1 30); do [ -n "$(port_owner "$PORT")" ] && break; sleep 1; done
[ -n "$(port_owner "$PORT")" ] || { journalctl -u "$SERVICE" -n 30 --no-pager >&2; die "service did not start listening on $PORT"; }
sleep 2
# Connect to this machine for the proxy hostname; credentials go via stdin, not argv.
check() { curl -s -o /dev/null --max-time 20 --resolve "$DOMAIN:$PORT:127.0.0.1" --proxy "https://$DOMAIN:$PORT" "$@" 2>/dev/null || true; }
ok=$(printf 'proxy-user = "%s:%s"\n' "$P_USER" "$P_PASS" | check -K - -w '%{http_code}' "$HEALTH_URL")
if [ "$ok" = 200 ]; then info "health check: authenticated tunnel works (HTTP 200 via proxy)"
else warn "health check through the proxy returned '$ok' (journalctl -u $SERVICE). Certificate or outbound network problem?"; fi
deny=$(check -w '%{http_connect}' "$HEALTH_URL")
expected=407; [ "$STEALTH" = 1 ] && expected=404
if [ "$deny" = "$expected" ]; then info "health check: unauthenticated request rejected ($deny)"
else warn "unauthenticated request returned '$deny', expected $expected"; fi

echo
info "deployed $REF@$COMMIT on $DOMAIN:$PORT (logs: journalctl -u $SERVICE -f)"
echo "Also allow inbound TCP $PORT$([ "$CERT_MODE" = certbot ] && echo ' and 80') in your cloud provider's security group if it has one."
echo
show_links
