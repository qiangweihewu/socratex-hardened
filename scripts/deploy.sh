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
  --cert MODE           Certificate source (asked interactively on first install):
                          existing  use certificate files already on this server
                                    (default /etc/letsencrypt/live/DOMAIN/fullchain.pem)
                          certbot   request a new Let's Encrypt certificate with certbot
                                    (needs port 80 free during issuance)
                          builtin   Socratex's built-in ACME client obtains and renews it
                                    (keeps port 80 open permanently for the HTTP-01 challenge)
  --cert-file PATH      Certificate chain for --cert existing (implies it)
  --key-file PATH       Private key for --cert existing (default: privkey.pem next to the chain)
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
ACTION=install DOMAIN="" EMAIL="" PORT="" P_USER="" P_PASS="" STEALTH="" CERT_ARG="" CERT_FILE="" KEY_FILE=""
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
        --cert) CERT_ARG="${2:-}"; shift ;;
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
            DEPLOY_CERT_FILE) OLD_CERT_FILE="$value" ;; DEPLOY_KEY_FILE) OLD_KEY_FILE="$value" ;;
        esac
    done < "$ENV_FILE"
}
OLD_USER="" OLD_PASS="" OLD_DOMAIN="" OLD_PORT="" OLD_SECRET="" OLD_STEALTH="" OLD_REF="" OLD_REPO="" OLD_NAME="" OLD_CERT=""
OLD_CERT_FILE="" OLD_KEY_FILE=""
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
    systemctl disable --now "$SERVICE-cert.path" >/dev/null 2>&1 || true
    rm -f "$UNIT" "$HOOK" "$ETC/cert-sync.sh" "/etc/systemd/system/$SERVICE-cert.path" "/etc/systemd/system/$SERVICE-cert.service"
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
# ---------- certificate mode ----------
# existing: copy chain/key from files already on the server (renewals are picked up by a
#           certbot deploy hook for /etc/letsencrypt/live/*, otherwise by a systemd path unit)
# certbot:  issue a Let's Encrypt certificate with certbot standalone if none exists, then as existing
# builtin:  Socratex's own ACME client (utilitas ssl, HTTP-01 on port 80) obtains and renews it
LE_LIVE=/etc/letsencrypt/live
prev_mode="$OLD_CERT"; [ "$prev_mode" = custom ] && prev_mode=existing # pre-2026-11-18 name
if [ -n "$CERT_ARG" ]; then CERT_MODE="$CERT_ARG"
elif [ -n "$CERT_FILE$KEY_FILE" ]; then CERT_MODE=existing
elif [ -n "$prev_mode" ]; then CERT_MODE="$prev_mode"
elif [ -t 0 ] && [ -t 1 ]; then
    default_choice=2; [ -r "$LE_LIVE/$DOMAIN/fullchain.pem" ] && default_choice=1
    echo
    echo "Certificate for $DOMAIN:"
    echo "  1) Use an existing certificate on this server (default $LE_LIVE/$DOMAIN/fullchain.pem)"
    echo "  2) Request a new Let's Encrypt certificate with certbot (needs port 80 free)"
    echo "  3) Built-in: Socratex obtains and renews it itself (keeps port 80 open)"
    read -r -p "Choose [1-3] (default $default_choice): " choice
    case "${choice:-$default_choice}" in
        1) CERT_MODE=existing ;; 2) CERT_MODE=certbot ;; 3) CERT_MODE=builtin ;;
        *) die "invalid choice: $choice" ;;
    esac
elif [ -r "$LE_LIVE/$DOMAIN/fullchain.pem" ]; then CERT_MODE=existing
else CERT_MODE=certbot
fi
case "$CERT_MODE" in existing|certbot|builtin) ;; *) die "--cert must be existing, certbot or builtin (got '$CERT_MODE')" ;; esac
[ "$CERT_MODE" = existing ] || [ -z "$CERT_FILE$KEY_FILE" ] || die "--cert-file/--key-file only apply to --cert existing"
CERT_SRC="" KEY_SRC=""
if [ "$CERT_MODE" = existing ]; then
    if [ -z "$CERT_FILE" ] && [ -z "$KEY_FILE" ] && [ -n "$OLD_CERT_FILE" ]; then
        CERT_FILE="$OLD_CERT_FILE"; KEY_FILE="$OLD_KEY_FILE"
    fi
    if [ -z "$CERT_FILE" ] && [ "$OLD_CERT" = custom ]; then
        CERT_FILE="$TLS_DIR/fullchain.pem"; KEY_FILE="$TLS_DIR/privkey.pem" # old installs kept no source path
    fi
    if [ -z "$CERT_FILE" ] && [ -t 0 ] && [ -t 1 ]; then
        read -r -p "Certificate chain [$LE_LIVE/$DOMAIN/fullchain.pem]: " CERT_FILE
        CERT_FILE="${CERT_FILE:-$LE_LIVE/$DOMAIN/fullchain.pem}"
        read -r -p "Private key [$(dirname "$CERT_FILE")/privkey.pem]: " KEY_FILE
    fi
    CERT_SRC="${CERT_FILE:-$LE_LIVE/$DOMAIN/fullchain.pem}"
    KEY_SRC="${KEY_FILE:-$(dirname "$CERT_SRC")/privkey.pem}"
    [[ "$CERT_SRC" == /* && "$KEY_SRC" == /* ]] || die "certificate paths must be absolute"
    [ -r "$CERT_SRC" ] || die "certificate not found: $CERT_SRC (use --cert certbot or --cert builtin to get one)"
    [ -r "$KEY_SRC" ] || die "private key not found: $KEY_SRC (pass --key-file)"
elif [ "$CERT_MODE" = certbot ]; then
    CERT_SRC="$LE_LIVE/$DOMAIN/fullchain.pem"; KEY_SRC="$LE_LIVE/$DOMAIN/privkey.pem"
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
if [ "$CERT_MODE" = certbot ] && [ ! -r "$CERT_SRC" ]; then
    owner="$(port_owner 80)"; [ -z "$owner" ] || die "certbot needs port 80 free for the HTTP-01 challenge, but it is used by: $owner (free it, or use --cert existing / --cert builtin)"
fi
if [ "$CERT_MODE" = builtin ]; then
    owner="$(port_owner 80)"
    [ -z "$owner" ] || [[ "$owner" == *'"node"'* && "$(systemctl is-active "$SERVICE" 2>/dev/null)" = active ]] \
        || die "--cert builtin keeps port 80 open for the ACME HTTP-01 challenge, but it is used by: $owner"
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
# Without --cert/--key Socratex runs its built-in ACME client (lib: utilitas ssl).
TLS_ARGS="--cert=$TLS_DIR/fullchain.pem --key=$TLS_DIR/privkey.pem"; [ "$CERT_MODE" = builtin ] && TLS_ARGS=""

# ---------- certificate ----------
SYNC="$ETC/cert-sync.sh"
CERT_UNIT="$SERVICE-cert"
key_fingerprint() { openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | sha256sum; }
cert_fingerprint() { openssl x509 -noout -pubkey -in "$1" 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum; }
remove_cert_sync() {
    rm -f "$HOOK" "$SYNC"
    systemctl disable --now "$CERT_UNIT.path" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$CERT_UNIT.path" "/etc/systemd/system/$CERT_UNIT.service"
}
remove_cert_sync
if [ "$CERT_MODE" = builtin ]; then
    info "certificate: Socratex's built-in ACME client will obtain and renew it (HTTP-01 on port 80)"
else
    if [ "$CERT_MODE" = certbot ] && [ ! -r "$CERT_SRC" ]; then
        info "requesting a Let's Encrypt certificate for $DOMAIN"
        args=(certonly --standalone --preferred-challenges http --non-interactive --agree-tos -d "$DOMAIN")
        if [ -n "$EMAIL" ]; then args+=(-m "$EMAIL"); else args+=(--register-unsafely-without-email); fi
        if certbot --help all 2>/dev/null | grep -- '--key-type' >/dev/null; then args+=(--key-type ecdsa); fi
        certbot "${args[@]}" || die "certbot failed: check that $DOMAIN points here and inbound TCP 80 is open (firewall / cloud security group)"
    fi
    [[ "$CERT_SRC" =~ ^/[A-Za-z0-9._/@+-]+$ && "$KEY_SRC" =~ ^/[A-Za-z0-9._/@+-]+$ ]] \
        || die "certificate paths may only contain letters, digits and . _ / @ + -"
    openssl x509 -noout -checkhost "$DOMAIN" -in "$CERT_SRC" 2>/dev/null | grep 'does match' >/dev/null \
        || die "$CERT_SRC is not a certificate for $DOMAIN"
    [ "$(cert_fingerprint "$CERT_SRC")" = "$(key_fingerprint "$KEY_SRC")" ] || die "$KEY_SRC is not the private key of $CERT_SRC"
    openssl x509 -noout -checkend 604800 -in "$CERT_SRC" >/dev/null || warn "the certificate expires within 7 days"
    if [ "$CERT_SRC" != "$TLS_DIR/fullchain.pem" ]; then
        # One script copies the pair into place and restarts the service. It runs now,
        # from certbot after renewals of a /etc/letsencrypt/live lineage, or from a path unit.
        cat > "$SYNC" <<EOF
#!/bin/sh
# Installed by socratex deploy.sh: copy the certificate into place and restart.
set -e
[ "\${1:-}" = --delay ] && sleep 5  # path unit: let the writer finish both files
cert=$CERT_SRC key=$KEY_SRC
a=\$(openssl x509 -noout -pubkey -in "\$cert" | openssl pkey -pubin -outform DER | sha256sum)
b=\$(openssl pkey -in "\$key" -pubout -outform DER | sha256sum)
[ "\$a" = "\$b" ] || { echo "\$cert and \$key do not match; not updating" >&2; exit 1; }
install -m 640 -o root -g $SERVICE "\$cert" $TLS_DIR/fullchain.pem
install -m 640 -o root -g $SERVICE "\$key" $TLS_DIR/privkey.pem
[ "\${1:-}" = --no-restart ] && exit 0
if systemctl is-enabled --quiet $SERVICE 2>/dev/null; then systemctl restart $SERVICE; fi
EOF
        chmod 700 "$SYNC"
        "$SYNC" --no-restart
        if [[ "$CERT_SRC" =~ ^/etc/letsencrypt/live/([^/]+)/ ]]; then
            lineage="/etc/letsencrypt/live/${BASH_REMATCH[1]}"
            mkdir -p "$(dirname "$HOOK")"
            cat > "$HOOK" <<EOF
#!/bin/sh
# Installed by socratex deploy.sh: pick up renewals of $lineage.
[ "\$RENEWED_LINEAGE" = "$lineage" ] || exit 0
exec $SYNC
EOF
            chmod 755 "$HOOK"
            CERT_RENEWAL="certbot deploy hook for $lineage"
        else
            cat > "/etc/systemd/system/$CERT_UNIT.service" <<EOF
[Unit]
Description=Socratex: install the renewed certificate

[Service]
Type=oneshot
ExecStart=$SYNC --delay
EOF
            cat > "/etc/systemd/system/$CERT_UNIT.path" <<EOF
[Unit]
Description=Socratex: watch $CERT_SRC for renewals

[Path]
PathChanged=$CERT_SRC
PathChanged=$KEY_SRC

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable -q --now "$CERT_UNIT.path"
            CERT_RENEWAL="systemd path unit $CERT_UNIT.path copies the files again when they change"
        fi
    else
        CERT_RENEWAL="none: replace $TLS_DIR/*.pem yourself and restart $SERVICE"
    fi
    info "certificate: $CERT_SRC ($CERT_MODE); renewals: $CERT_RENEWAL"
fi

# ---------- settings ----------
tmp_env="$(mktemp)"
cat > "$tmp_env" <<EOF
SOCRATEX_USER=$P_USER
SOCRATEX_PASSWORD=$P_PASS
SOCRATEX_DOMAIN=$DOMAIN
SOCRATEX_PORT=$PORT
SOCRATEX_SECRET_DOMAIN=$SECRET_DOMAIN
SOCRATEX_EXTRA_ARGS=$EXTRA_ARGS
SOCRATEX_TLS_ARGS=$TLS_ARGS
DEPLOY_STEALTH=$STEALTH
DEPLOY_REF=$REF
DEPLOY_REPO=$REPO_URL
DEPLOY_NAME=$NAME
DEPLOY_CERT=$CERT_MODE
DEPLOY_CERT_FILE=$([ "$CERT_MODE" = existing ] && echo "$CERT_SRC" || true)
DEPLOY_KEY_FILE=$([ "$CERT_MODE" = existing ] && echo "$KEY_SRC" || true)
EOF
install -m 600 -o root -g root "$tmp_env" "$ENV_FILE"; rm -f "$tmp_env"

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
ExecStart=$NODE main.mjs --domain=\${SOCRATEX_DOMAIN} --port=\${SOCRATEX_PORT} \$SOCRATEX_TLS_ARGS \$SOCRATEX_EXTRA_ARGS
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
FW_PORTS=("$PORT/tcp"); { [ "$CERT_MODE" = certbot ] || [ "$CERT_MODE" = builtin ]; } && FW_PORTS+=(80/tcp)
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
tunnel() { printf 'proxy-user = "%s:%s"\n' "$P_USER" "$P_PASS" | check -K - -w '%{http_code}' "$HEALTH_URL"; }
TRIES=1; [ "$CERT_MODE" = builtin ] && TRIES=36
[ "$TRIES" = 1 ] || info "waiting for the built-in ACME client to obtain the certificate (up to 3 minutes)"
for i in $(seq 1 "$TRIES"); do
    ok=$(tunnel); [ "$ok" = 200 ] && break
    [ "$i" = "$TRIES" ] || sleep 5
done
if [ "$ok" = 200 ]; then info "health check: authenticated tunnel works (HTTP 200 via proxy)"
else warn "health check through the proxy returned '$ok' (journalctl -u $SERVICE). Certificate or outbound network problem?"; fi
deny=$(check -w '%{http_connect}' "$HEALTH_URL")
expected=407; [ "$STEALTH" = 1 ] && expected=404
if [ "$deny" = "$expected" ]; then info "health check: unauthenticated request rejected ($deny)"
else warn "unauthenticated request returned '$deny', expected $expected"; fi

echo
info "deployed $REF@$COMMIT on $DOMAIN:$PORT (logs: journalctl -u $SERVICE -f)"
echo "Also allow inbound TCP $PORT$([ "$CERT_MODE" != existing ] && echo ' and 80') in your cloud provider's security group if it has one."
echo
show_links
