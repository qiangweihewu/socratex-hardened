#!/usr/bin/env bash
# One-step AnyTLS / ShadowTLS v3 / NaïveProxy server deployment for Debian/Ubuntu (systemd).
#
#   sudo bash deploy-protocols.sh --domain proxy.example.com [--email you@example.com]
#   sudo bash deploy-protocols.sh --protocols anytls,shadowtls --domain proxy.example.com
#   sudo bash deploy-protocols.sh --show                # print client links again
#   sudo bash deploy-protocols.sh --uninstall [--purge]
#
# AnyTLS and ShadowTLS run in sing-box (https://github.com/SagerNet/sing-box).
# NaïveProxy runs in Caddy with klzgrad/forwardproxy, the official naive server
# (https://github.com/klzgrad/forwardproxy). Both binaries are downloaded from
# their GitHub releases and checked against the SHA-256 digest GitHub publishes.
# Re-running the script updates both binaries and keeps every setting.
set -Eeuo pipefail
umask 022

BASE=/opt/sx-proto
BIN="$BASE/bin"
ETC=/etc/sx-proto
SETTINGS="$ETC/settings.env"
TLS_DIR="$ETC/tls"
SB_CONF="$ETC/sing-box.json"
CADDYFILE="$ETC/Caddyfile"
LINKS_FILE="$ETC/client-links.txt"
STATE=/var/lib/sx-proto
WWW="$STATE/www"
SVC_USER=sx-proto
SB_SERVICE=sx-proto-singbox
NAIVE_SERVICE=sx-proto-naive
HOOK=/etc/letsencrypt/renewal-hooks/deploy/sx-proto.sh
HEALTH_URL="https://www.gstatic.com/generate_204"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO: $BASH_COMMAND"' ERR

usage() {
    cat <<'EOF'
Usage: sudo bash deploy-protocols.sh --domain DOMAIN [options]
       sudo bash deploy-protocols.sh --show | --uninstall [--purge]

Install / update (settings are kept between runs):
  --protocols LIST       Comma-separated: anytls,shadowtls,naive (default: all three)
  --domain DOMAIN        Hostname pointing at this server; needed for anytls and naive
                         (they need a certificate for it)
  --address HOST         Address clients connect to for shadowtls when no --domain is given
                         (default: this machine's outbound IPv4 address)
  --cert MODE            Certificate for anytls/naive (asked interactively on first install):
                           existing  use certificate files already on this server
                                     (default /etc/letsencrypt/live/DOMAIN/fullchain.pem)
                           certbot   request a new Let's Encrypt certificate with certbot
                                     (needs port 80 free during issuance)
                           builtin   let Caddy / sing-box obtain and renew it themselves
                                     (needs port 80 free, or a protocol on port 443)
  --cert-file PATH       Certificate chain for --cert existing (implies it)
  --key-file PATH        Private key for --cert existing (default: privkey.pem next to the chain)
  --email EMAIL          ACME account e-mail (certbot / builtin)
  --naive-port PORT      NaïveProxy port (default 443)
  --anytls-port PORT     AnyTLS port (default 8443)
  --shadowtls-port PORT  ShadowTLS port (default 9443)
  --shadowtls-sni HOST   Real TLS 1.3 site that ShadowTLS borrows the handshake from
                         (default www.microsoft.com; clients must use the same value)
  --name NAME            Profile name prefix in client links (default: sx)
  --regenerate           Replace all passwords with new random ones

Other:
  --show                 Print the client configuration again
  --uninstall            Stop and remove services and binaries (keeps settings)
  --purge                With --uninstall: also delete settings, state and the service user
EOF
}

# ---------- arguments ----------
ACTION=install PROTOCOLS="" DOMAIN="" ADDRESS="" EMAIL="" CERT_ARG="" CERT_FILE="" KEY_FILE=""
NAIVE_PORT="" ANYTLS_PORT="" SHADOWTLS_PORT="" SHADOWTLS_SNI="" NAME="" REGEN=0 PURGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --protocols) PROTOCOLS="${2:-}"; shift ;;
        --domain) DOMAIN="${2:-}"; shift ;;
        --address) ADDRESS="${2:-}"; shift ;;
        --email) EMAIL="${2:-}"; shift ;;
        --cert) CERT_ARG="${2:-}"; shift ;;
        --cert-file) CERT_FILE="${2:-}"; shift ;;
        --key-file) KEY_FILE="${2:-}"; shift ;;
        --naive-port) NAIVE_PORT="${2:-}"; shift ;;
        --anytls-port) ANYTLS_PORT="${2:-}"; shift ;;
        --shadowtls-port) SHADOWTLS_PORT="${2:-}"; shift ;;
        --shadowtls-sni) SHADOWTLS_SNI="${2:-}"; shift ;;
        --name) NAME="${2:-}"; shift ;;
        --regenerate) REGEN=1 ;;
        --show) ACTION=show ;;
        --uninstall) ACTION=uninstall ;;
        --purge) PURGE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
    shift
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash deploy-protocols.sh ...)"
[ "$(uname -s)" = Linux ] || die "Linux only"

# Settings from a previous run (root-only KEY=value file written by this script).
declare -A OLD=()
load_settings() {
    [ -f "$SETTINGS" ] || return 0
    local key value
    while IFS='=' read -r key value; do
        if [[ "$key" =~ ^[A-Z_]+$ ]]; then OLD[$key]="$value"; fi
    done < "$SETTINGS"
}
load_settings
old() { printf '%s' "${OLD[$1]:-}"; }
has() { [[ ",$PROTOCOLS," == *",$1,"* ]]; }
# URL-safe base64 without padding (SIP002 style).
b64url() { printf '%s' "$1" | base64 -w0 | tr '+/' '-_' | tr -d '='; }
# Shadowrocket import links, in the format Shadowrocket itself exports.
sr_https() { # user pass host port name
    printf 'https://%s:%s@%s:%s?peer=%s&method=auto&fingerprint=Safari26_3#%s' "$1" "$2" "$3" "$4" "$3" "$5"
}
sr_shadowtls() { # ss-method ss-password host port sni shadowtls-password name
    # Build the JSON in a variable: braces inside "$(...)" are brace-expanded by bash 3.2.
    local json="{\"version\":\"3\",\"host\":\"$5\",\"password\":\"$6\"}"
    printf 'ss://%s?shadow-tls=%s#%s' "$(b64url "$1:$2@$3:$4")" "$(b64url "$json")" "$7"
}

# ---------- client configuration ----------
show_links() {
    [ -f "$SETTINGS" ] || die "not installed yet ($SETTINGS missing)"
    OLD=(); load_settings
    local name protocols host
    name="$(old NAME)"; protocols="$(old PROTOCOLS)"; host="$(old DOMAIN)"; host="${host:-$(old ADDRESS)}"
    PROTOCOLS="$protocols"
    {
        echo "============ sx-proto client configuration ($host) ============"
        if has naive; then
            local u p port; u="$(old NAIVE_USER)"; p="$(old NAIVE_PASSWORD)"; port="$(old NAIVE_PORT)"
            echo
            echo "################ NaïveProxy (Caddy + forwardproxy), TCP $port ################"
            echo "[Link] NekoBox / husi / Exclave / v2rayN (import from clipboard):"
            echo "naive+https://$u:$p@$host:$port#$name-naive"
            echo
            echo "[naive CLI] config.json \"proxy\": https://$u:$p@$host:$port"
            echo
            echo "[Clash Meta / mihomo] plain HTTPS proxy (no naive padding), add under proxies:"
            echo "  - name: $name-naive"
            echo "    type: http"
            echo "    server: $host"
            echo "    port: $port"
            echo "    username: $u"
            echo "    password: $p"
            echo "    tls: true"
            echo "    sni: $host"
            echo
            echo "[Shadowrocket] import from clipboard:"
            sr_https "$u" "$p" "$host" "$port" "$name-naive"; echo
            echo "  This server negotiates HTTP/2: after importing, turn HTTP2 ON in the node's TLS settings"
            echo "  (or set ALPN to http/1.1), and turn Padding (填充) on for naive padding."
            echo
            echo "[Test] curl -sS -o /dev/null -w '%{http_code}\\n' --proxy 'https://$u:$p@$host:$port' $HEALTH_URL"
        fi
        if has anytls; then
            local ap aport; ap="$(old ANYTLS_PASSWORD)"; aport="$(old ANYTLS_PORT)"
            echo
            echo "################ AnyTLS (sing-box), TCP $aport ################"
            echo "[Link] anytls:// URI (format from anytls-go docs/uri_scheme.md; import in clients that support AnyTLS):"
            echo "anytls://$ap@$host:$aport/?sni=$host#$name-anytls"
            echo
            echo "[Clash Meta / mihomo] add under proxies:"
            echo "  - name: $name-anytls"
            echo "    type: anytls"
            echo "    server: $host"
            echo "    port: $aport"
            echo "    password: $ap"
            echo "    sni: $host"
            echo "    client-fingerprint: chrome"
            echo "    udp: true"
            echo
            echo "[sing-box] outbound:"
            echo "  {\"type\": \"anytls\", \"tag\": \"$name-anytls\", \"server\": \"$host\", \"server_port\": $aport,"
            echo "   \"password\": \"$ap\", \"tls\": {\"enabled\": true, \"server_name\": \"$host\","
            echo "   \"utls\": {\"enabled\": true, \"fingerprint\": \"chrome\"}}}"
        fi
        if has shadowtls; then
            local sp sport sni ssp; sp="$(old SHADOWTLS_PASSWORD)"; sport="$(old SHADOWTLS_PORT)"
            sni="$(old SHADOWTLS_SNI)"; ssp="$(old SS_PASSWORD)"
            echo
            echo "################ ShadowTLS v3 + Shadowsocks 2022 (sing-box), TCP $sport ################"
            echo "Server $host:$sport | ShadowTLS v3 password $sp | SNI / handshake host $sni"
            echo "Shadowsocks method 2022-blake3-aes-128-gcm | password $ssp | TCP only (no UDP)"
            echo "(There is no standard share link for ShadowTLS; use one of the configs below.)"
            echo
            echo "[Clash Meta / mihomo] add under proxies:"
            echo "  - name: $name-shadowtls"
            echo "    type: ss"
            echo "    server: $host"
            echo "    port: $sport"
            echo "    cipher: 2022-blake3-aes-128-gcm"
            echo "    password: \"$ssp\""
            echo "    udp: false"
            echo "    client-fingerprint: chrome"
            echo "    plugin: shadow-tls"
            echo "    plugin-opts:"
            echo "      host: $sni"
            echo "      password: \"$sp\""
            echo "      version: 3"
            echo
            echo "[sing-box] outbounds (both entries are needed):"
            echo "  {\"type\": \"shadowsocks\", \"tag\": \"$name-shadowtls\", \"method\": \"2022-blake3-aes-128-gcm\","
            echo "   \"password\": \"$ssp\", \"detour\": \"$name-shadowtls-tls\"},"
            echo "  {\"type\": \"shadowtls\", \"tag\": \"$name-shadowtls-tls\", \"server\": \"$host\", \"server_port\": $sport,"
            echo "   \"version\": 3, \"password\": \"$sp\", \"tls\": {\"enabled\": true, \"server_name\": \"$sni\","
            echo "   \"utls\": {\"enabled\": true, \"fingerprint\": \"chrome\"}}}"
            echo
            echo "[Shadowrocket] import from clipboard (Shadowsocks node with the shadow-tls plugin):"
            sr_shadowtls 2022-blake3-aes-128-gcm "$ssp" "$host" "$sport" "$sni" "$sp" "$name-shadowtls"; echo
        fi
        echo
        echo "Keep these credentials private. Show again: sudo bash deploy-protocols.sh --show"
        echo "================================================================"
    } | (umask 077; tee "$LINKS_FILE")
    if command -v qrencode >/dev/null 2>&1; then
        if has naive; then
            echo; echo "NaïveProxy link as QR code:"
            qrencode -t ANSIUTF8 "naive+https://$(old NAIVE_USER):$(old NAIVE_PASSWORD)@$host:$(old NAIVE_PORT)#$name-naive"
        fi
        if has anytls; then
            echo; echo "AnyTLS link as QR code:"
            qrencode -t ANSIUTF8 "anytls://$(old ANYTLS_PASSWORD)@$host:$(old ANYTLS_PORT)/?sni=$host#$name-anytls"
        fi
        if has shadowtls; then
            echo; echo "ShadowTLS Shadowrocket link as QR code:"
            qrencode -t ANSIUTF8 "$(sr_shadowtls 2022-blake3-aes-128-gcm "$(old SS_PASSWORD)" "$host" \
                "$(old SHADOWTLS_PORT)" "$(old SHADOWTLS_SNI)" "$(old SHADOWTLS_PASSWORD)" "$name-shadowtls")"
        fi
    fi
}

# ---------- uninstall ----------
uninstall() {
    info "stopping and removing services"
    for svc in "$SB_SERVICE" "$NAIVE_SERVICE"; do
        systemctl disable --now "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/$svc.service"
    done
    systemctl disable --now sx-proto-cert.path >/dev/null 2>&1 || true
    rm -f "$HOOK" "$ETC/cert-sync.sh" /etc/systemd/system/sx-proto-cert.path /etc/systemd/system/sx-proto-cert.service
    systemctl daemon-reload
    rm -rf "$BASE"
    if [ "$PURGE" -eq 1 ]; then
        info "purging settings, state and the service user"
        rm -rf "$ETC" "$STATE"
        id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" || true
        [ -n "$(old DOMAIN)" ] && [ -d "/etc/letsencrypt/live/$(old DOMAIN)" ] && \
            echo "The Let's Encrypt certificate is kept; remove it with: certbot delete --cert-name $(old DOMAIN)"
    else
        echo "Settings kept in $ETC (use --uninstall --purge to delete them)."
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
random_alnum() { tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1" || true; }
keep() { [ "$REGEN" = 1 ] && return 0; old "$1"; } # previous value unless --regenerate

PROTOCOLS="${PROTOCOLS:-$(old PROTOCOLS)}"; PROTOCOLS="${PROTOCOLS:-anytls,shadowtls,naive}"
PROTOCOLS="${PROTOCOLS// /}"; PROTOCOLS="${PROTOCOLS,,}"
IFS=',' read -r -a proto_list <<< "$PROTOCOLS"
[ "${#proto_list[@]}" -gt 0 ] || die "--protocols is empty"
for p in "${proto_list[@]}"; do
    case "$p" in anytls|shadowtls|naive) ;; *) die "unknown protocol '$p' (use anytls, shadowtls, naive)" ;; esac
done

DOMAIN="${DOMAIN:-$(old DOMAIN)}"; DOMAIN="${DOMAIN,,}"
NEED_CERT=0; { has anytls || has naive; } && NEED_CERT=1
if [ -n "$DOMAIN" ]; then
    [[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "invalid domain: $DOMAIN"
elif [ "$NEED_CERT" = 1 ]; then
    die "--domain is required for anytls and naive"
fi
[ -z "$EMAIL" ] || [[ "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die "invalid e-mail: $EMAIL"
NAME="${NAME:-$(old NAME)}"; NAME="${NAME:-sx}"
[[ "$NAME" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || die "--name must be 1-32 chars of [A-Za-z0-9._-]"

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
NAIVE_PORT="${NAIVE_PORT:-$(old NAIVE_PORT)}"; NAIVE_PORT="${NAIVE_PORT:-443}"
ANYTLS_PORT="${ANYTLS_PORT:-$(old ANYTLS_PORT)}"; ANYTLS_PORT="${ANYTLS_PORT:-8443}"
SHADOWTLS_PORT="${SHADOWTLS_PORT:-$(old SHADOWTLS_PORT)}"; SHADOWTLS_PORT="${SHADOWTLS_PORT:-9443}"
USED_PORTS=()
has naive && USED_PORTS+=("$NAIVE_PORT")
has anytls && USED_PORTS+=("$ANYTLS_PORT")
has shadowtls && USED_PORTS+=("$SHADOWTLS_PORT")
for port in "${USED_PORTS[@]}"; do valid_port "$port" || die "invalid port: $port"; done
[ "$(printf '%s\n' "${USED_PORTS[@]}" | sort -u | wc -l)" -eq "${#USED_PORTS[@]}" ] \
    || die "each protocol needs its own port (got ${USED_PORTS[*]})"

SHADOWTLS_SNI="${SHADOWTLS_SNI:-$(old SHADOWTLS_SNI)}"; SHADOWTLS_SNI="${SHADOWTLS_SNI:-www.microsoft.com}"
SHADOWTLS_SNI="${SHADOWTLS_SNI,,}"
[[ "$SHADOWTLS_SNI" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] \
    || die "invalid --shadowtls-sni: $SHADOWTLS_SNI"

NAIVE_USER="$(keep NAIVE_USER)"; NAIVE_USER="${NAIVE_USER:-u$(random_alnum 7)}"
NAIVE_PASSWORD="$(keep NAIVE_PASSWORD)"; NAIVE_PASSWORD="${NAIVE_PASSWORD:-$(random_alnum 32)}"
ANYTLS_PASSWORD="$(keep ANYTLS_PASSWORD)"; ANYTLS_PASSWORD="${ANYTLS_PASSWORD:-$(random_alnum 32)}"
SHADOWTLS_PASSWORD="$(keep SHADOWTLS_PASSWORD)"; SHADOWTLS_PASSWORD="${SHADOWTLS_PASSWORD:-$(random_alnum 32)}"
# Shadowsocks 2022 (aes-128) keys are 16 random bytes in base64.
SS_PASSWORD="$(keep SS_PASSWORD)"; SS_PASSWORD="${SS_PASSWORD:-$(head -c 16 /dev/urandom | base64)}"

# ---------- certificate mode ----------
# existing: copy chain/key from files already on the server (renewals are picked up by a
#           certbot deploy hook for /etc/letsencrypt/live/*, otherwise by a systemd path unit)
# certbot:  issue a Let's Encrypt certificate with certbot standalone if none exists, then as existing
# builtin:  Caddy (naive) and sing-box (anytls) run ACME themselves, sharing one certificate store
LE_LIVE=/etc/letsencrypt/live
CERT_MODE="" CERT_SRC="" KEY_SRC=""
if [ "$NEED_CERT" = 1 ]; then
    prev_mode="$(old CERT_MODE)"; [ "$prev_mode" = custom ] && prev_mode=existing # pre-2026-11-18 name
    if [ -n "$CERT_ARG" ]; then CERT_MODE="$CERT_ARG"
    elif [ -n "$CERT_FILE$KEY_FILE" ]; then CERT_MODE=existing
    elif [ -n "$prev_mode" ]; then CERT_MODE="$prev_mode"
    elif [ -t 0 ] && [ -t 1 ]; then
        default_choice=2; [ -r "$LE_LIVE/$DOMAIN/fullchain.pem" ] && default_choice=1
        echo
        echo "Certificate for $DOMAIN (used by anytls and naive):"
        echo "  1) Use an existing certificate on this server (default $LE_LIVE/$DOMAIN/fullchain.pem)"
        echo "  2) Request a new Let's Encrypt certificate with certbot (needs port 80 free)"
        echo "  3) Built-in: Caddy / sing-box obtain and renew it automatically (needs port 80 free)"
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

    if [ "$CERT_MODE" = existing ]; then
        if [ -z "$CERT_FILE" ] && [ -z "$KEY_FILE" ] && [ -n "$(old CERT_FILE)" ]; then
            CERT_FILE="$(old CERT_FILE)"; KEY_FILE="$(old KEY_FILE)"
        fi
        if [ -z "$CERT_FILE" ] && [ "$(old CERT_MODE)" = custom ]; then
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
fi

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
esac
# klzgrad/forwardproxy only publishes an x86-64 build of Caddy.
if has naive && [ "$ARCH" != amd64 ]; then
    die "naive needs the official Caddy build, which is x86-64 only. On $ARCH use --protocols anytls,shadowtls, or Socratex (scripts/deploy.sh) which also speaks the naive protocol"
fi

port_owner() { ss -ltnpH "sport = :$1" 2>/dev/null | awk 'NR == 1' || true; }
check_port_free() { # $1 port, $2 process name allowed (our own service on re-runs)
    local owner; owner="$(port_owner "$1")"
    [ -z "$owner" ] || [[ "$owner" == *"\"$2\""* ]] || die "port $1 is already in use: $owner"
}

# ---------- packages ----------
info "installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
PKGS=(ca-certificates curl jq tar xz-utils iproute2 openssl qrencode)
[ "$NEED_CERT" = 1 ] && [ "$CERT_MODE" = certbot ] && PKGS+=(certbot)
apt-get install -y -qq --no-install-recommends "${PKGS[@]}" >/dev/null

# ---------- preflight ----------
has naive && check_port_free "$NAIVE_PORT" caddy
has anytls && check_port_free "$ANYTLS_PORT" sing-box
has shadowtls && check_port_free "$SHADOWTLS_PORT" sing-box
if [ "$CERT_MODE" = certbot ] && [ ! -r "$CERT_SRC" ]; then
    owner="$(port_owner 80)"; [ -z "$owner" ] || die "certbot needs port 80 free for the HTTP-01 challenge, but it is used by: $owner (free it, or use --cert existing / --cert builtin)"
fi
if [ "$CERT_MODE" = builtin ]; then
    # ACME needs HTTP-01 on port 80, or TLS-ALPN-01 on a protocol listening on 443.
    owner="$(port_owner 80)"
    on443=0; { { has naive && [ "$NAIVE_PORT" = 443 ]; } || { has anytls && [ "$ANYTLS_PORT" = 443 ]; }; } && on443=1
    if [ -n "$owner" ] && [[ "$owner" != *'"caddy"'* && "$owner" != *'"sing-box"'* ]]; then
        [ "$on443" = 1 ] || die "--cert builtin needs port 80 free for ACME (used by: $owner), or naive/anytls on port 443"
        warn "port 80 is busy ($owner); ACME will rely on the TLS-ALPN challenge on port 443"
    fi
fi
if [ -n "$DOMAIN" ]; then
    resolved="$(getent ahosts "$DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ' || true)"
    [ -n "$resolved" ] || die "$DOMAIN does not resolve; create its DNS record first"
    local_ips="$(ip -o addr show | awk '{split($4, a, "/"); print a[1]}' | sort -u | tr '\n' ' ')"
    match=0; for ip in $resolved; do [[ " $local_ips " == *" $ip "* ]] && match=1; done
    [ "$match" = 1 ] || warn "$DOMAIN resolves to [$resolved] which is not on this machine's interfaces. Fine behind NAT / elastic IP, otherwise fix DNS."
fi
ADDRESS="${ADDRESS:-$(old ADDRESS)}"
if [ -z "$DOMAIN" ] && [ -z "$ADDRESS" ]; then
    ADDRESS="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}' | awk 'NR == 1' || true)"
    [ -n "$ADDRESS" ] || die "could not detect this server's address; pass --address"
    warn "clients will connect to $ADDRESS (pass --address if the public address differs, e.g. behind NAT)"
fi
if has shadowtls; then
    # ShadowTLS v3 needs the handshake server to speak TLS 1.3.
    echo | timeout 15 openssl s_client -connect "$SHADOWTLS_SNI:443" -servername "$SHADOWTLS_SNI" -tls1_3 >/dev/null 2>&1 \
        || die "$SHADOWTLS_SNI:443 did not complete a TLS 1.3 handshake from this server; pick another --shadowtls-sni"
fi

# ---------- binaries (GitHub releases, SHA-256 checked) ----------
# $1 owner/repo, $2 jq filter selecting the asset; prints "name url sha256" of the latest release.
release_asset() {
    curl -fsSL -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/$1/releases/latest" \
        | jq -r "[.assets[] | select($2)][0] | \"\(.name) \(.browser_download_url) \(.digest // \"\")\""
}
fetch_verified() { # $1 url, $2 "sha256:<hex>", $3 output file
    [[ "$2" =~ ^sha256:[0-9a-f]{64}$ ]] || die "GitHub did not publish a SHA-256 digest for $1; refusing to install it"
    curl -fsSL "$1" -o "$3"
    echo "${2#sha256:}  $3" | sha256sum -c --status || die "checksum mismatch for $1"
}
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
install -d -m 755 "$BASE" "$BIN"

NEED_SB=0; { has anytls || has shadowtls; } && NEED_SB=1
if [ "$NEED_SB" = 1 ]; then
    read -r sb_name sb_url sb_sum < <(release_asset SagerNet/sing-box \
        ".name | test(\"^sing-box-[0-9.]+-linux-$ARCH\\\\.tar\\\\.gz$\")")
    [ -n "$sb_name" ] && [ "$sb_name" != null ] || die "no sing-box release found for linux-$ARCH"
    info "downloading $sb_name"
    fetch_verified "$sb_url" "$sb_sum" "$TMP/$sb_name"
    tar -xzf "$TMP/$sb_name" -C "$TMP"
    NEW_SB="$(find "$TMP" -type f -name sing-box -perm -u+x | awk 'NR == 1')"
    [ -n "$NEW_SB" ] || die "sing-box binary not found in $sb_name"
fi
if has naive; then
    read -r cd_name cd_url cd_sum < <(release_asset klzgrad/forwardproxy '.name == "caddy-forwardproxy-naive.tar.xz"')
    [ -n "$cd_name" ] && [ "$cd_name" != null ] || die "no caddy-forwardproxy-naive release found"
    info "downloading $cd_name ($(basename "$(dirname "$cd_url")"))"
    fetch_verified "$cd_url" "$cd_sum" "$TMP/$cd_name"
    tar -xJf "$TMP/$cd_name" -C "$TMP"
    NEW_CADDY="$TMP/caddy-forwardproxy-naive/caddy"
    [ -x "$NEW_CADDY" ] || die "caddy binary not found in $cd_name"
fi

# ---------- user, settings ----------
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin "$SVC_USER"
install -d -m 750 -o "$SVC_USER" -g "$SVC_USER" "$STATE"
install -d -m 755 "$ETC"
install -d -m 750 -o root -g "$SVC_USER" "$TLS_DIR"
# ---------- certificate ----------
RESTART_LIST="$SB_SERVICE $NAIVE_SERVICE"
SYNC="$ETC/cert-sync.sh"
CERT_UNIT=sx-proto-cert
key_fingerprint() { openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | sha256sum; }
cert_fingerprint() { openssl x509 -noout -pubkey -in "$1" 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum; }
check_cert() { # $1 chain, $2 key
    openssl x509 -noout -checkhost "$DOMAIN" -in "$1" 2>/dev/null | grep 'does match' >/dev/null \
        || die "$1 is not a certificate for $DOMAIN"
    [ "$(cert_fingerprint "$1")" = "$(key_fingerprint "$2")" ] || die "$2 is not the private key of $1"
    openssl x509 -noout -checkend 604800 -in "$1" >/dev/null || warn "the certificate expires within 7 days"
}
remove_cert_sync() {
    rm -f "$HOOK" "$SYNC"
    systemctl disable --now "$CERT_UNIT.path" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$CERT_UNIT.path" "/etc/systemd/system/$CERT_UNIT.service"
}
CERT_RENEWAL=""
remove_cert_sync
if [ "$NEED_CERT" = 1 ] && [ "$CERT_MODE" != builtin ]; then
    if [ "$CERT_MODE" = certbot ] && [ ! -r "$CERT_SRC" ]; then
        info "requesting a Let's Encrypt certificate for $DOMAIN"
        args=(certonly --standalone --preferred-challenges http --non-interactive --agree-tos -d "$DOMAIN")
        if [ -n "$EMAIL" ]; then args+=(-m "$EMAIL"); else args+=(--register-unsafely-without-email); fi
        if certbot --help all 2>/dev/null | grep -- '--key-type' >/dev/null; then args+=(--key-type ecdsa); fi
        certbot "${args[@]}" || die "certbot failed: check that $DOMAIN points here and inbound TCP 80 is open"
    fi
    [[ "$CERT_SRC" =~ ^/[A-Za-z0-9._/@+-]+$ && "$KEY_SRC" =~ ^/[A-Za-z0-9._/@+-]+$ ]] \
        || die "certificate paths may only contain letters, digits and . _ / @ + -"
    check_cert "$CERT_SRC" "$KEY_SRC"
    if [ "$CERT_SRC" != "$TLS_DIR/fullchain.pem" ]; then
        # One script copies the pair into place and restarts the services. It runs now,
        # from certbot after renewals of a /etc/letsencrypt/live lineage, or from a path unit.
        cat > "$SYNC" <<EOF
#!/bin/sh
# Installed by socratex scripts/deploy-protocols.sh: copy the certificate into place and restart.
set -e
[ "\${1:-}" = --delay ] && sleep 5  # path unit: let the writer finish both files
cert=$CERT_SRC key=$KEY_SRC
a=\$(openssl x509 -noout -pubkey -in "\$cert" | openssl pkey -pubin -outform DER | sha256sum)
b=\$(openssl pkey -in "\$key" -pubout -outform DER | sha256sum)
[ "\$a" = "\$b" ] || { echo "\$cert and \$key do not match; not updating" >&2; exit 1; }
install -m 640 -o root -g $SVC_USER "\$cert" $TLS_DIR/fullchain.pem
install -m 640 -o root -g $SVC_USER "\$key" $TLS_DIR/privkey.pem
[ "\${1:-}" = --no-restart ] && exit 0
for svc in $RESTART_LIST; do
    if systemctl is-enabled --quiet "\$svc" 2>/dev/null; then systemctl restart "\$svc"; fi
done
EOF
        chmod 700 "$SYNC"
        "$SYNC" --no-restart
        if [[ "$CERT_SRC" =~ ^/etc/letsencrypt/live/([^/]+)/ ]]; then
            lineage="/etc/letsencrypt/live/${BASH_REMATCH[1]}"
            mkdir -p "$(dirname "$HOOK")"
            cat > "$HOOK" <<EOF
#!/bin/sh
# Installed by socratex scripts/deploy-protocols.sh: pick up renewals of $lineage.
[ "\$RENEWED_LINEAGE" = "$lineage" ] || exit 0
exec $SYNC
EOF
            chmod 755 "$HOOK"
            CERT_RENEWAL="certbot deploy hook for $lineage"
        else
            cat > "/etc/systemd/system/$CERT_UNIT.service" <<EOF
[Unit]
Description=sx-proto: install the renewed certificate

[Service]
Type=oneshot
ExecStart=$SYNC --delay
EOF
            cat > "/etc/systemd/system/$CERT_UNIT.path" <<EOF
[Unit]
Description=sx-proto: watch $CERT_SRC for renewals

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
        CERT_RENEWAL="none: replace $TLS_DIR/*.pem yourself and restart the services"
    fi
    info "certificate: $CERT_SRC ($CERT_MODE); renewals: $CERT_RENEWAL"
elif [ "$CERT_MODE" = builtin ]; then
    info "certificate: obtained and renewed by Caddy / sing-box via ACME (store: $STATE/caddy)"
fi

tmp_set="$(mktemp)"
cat > "$tmp_set" <<EOF
PROTOCOLS=$PROTOCOLS
DOMAIN=$DOMAIN
ADDRESS=$ADDRESS
NAME=$NAME
CERT_MODE=$CERT_MODE
CERT_FILE=$([ "$CERT_MODE" = existing ] && echo "$CERT_SRC" || true)
KEY_FILE=$([ "$CERT_MODE" = existing ] && echo "$KEY_SRC" || true)
NAIVE_PORT=$NAIVE_PORT
NAIVE_USER=$NAIVE_USER
NAIVE_PASSWORD=$NAIVE_PASSWORD
ANYTLS_PORT=$ANYTLS_PORT
ANYTLS_PASSWORD=$ANYTLS_PASSWORD
SHADOWTLS_PORT=$SHADOWTLS_PORT
SHADOWTLS_SNI=$SHADOWTLS_SNI
SHADOWTLS_PASSWORD=$SHADOWTLS_PASSWORD
SS_PASSWORD=$SS_PASSWORD
EOF
install -m 600 -o root -g root "$tmp_set" "$SETTINGS"; rm -f "$tmp_set"


# ---------- systemd unit ----------
write_unit() { # $1 service, $2 description, $3 ExecStart
    cat > "/etc/systemd/system/$1.service" <<EOF
[Unit]
Description=$2
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
Environment=HOME=$STATE XDG_DATA_HOME=$STATE XDG_CONFIG_HOME=$STATE
WorkingDirectory=$STATE
ExecStart=$3
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
}
disable_service() {
    if [ -f "/etc/systemd/system/$1.service" ]; then
        info "protocol removed from --protocols: disabling $1"
        systemctl disable --now "$1" 2>/dev/null || true
        rm -f "/etc/systemd/system/$1.service"
    fi
}

# ---------- sing-box: AnyTLS + ShadowTLS v3 ----------
if [ "$NEED_SB" = 1 ]; then
    info "writing sing-box configuration"
    inbounds="[]"
    if has anytls; then
        # builtin: sing-box's ACME provider stores into Caddy's certmagic directory, so
        # naive and anytls share one certificate and coordinate through its lock files.
        inbounds="$(jq -c --arg port "$ANYTLS_PORT" --arg name "$NAME" --arg pw "$ANYTLS_PASSWORD" \
            --arg domain "$DOMAIN" --arg tls "$TLS_DIR" --arg mode "$CERT_MODE" --arg store "$STATE/caddy" \
            --arg email "$EMAIL" '. + [{
                type: "anytls", tag: "anytls-in", listen: "::", listen_port: ($port | tonumber),
                users: [{name: $name, password: $pw}],
                tls: ({enabled: true, server_name: $domain} + (if $mode == "builtin" then {
                        certificate_provider: ({type: "acme", domain: [$domain], data_directory: $store,
                            default_server_name: $domain, key_type: "p256"}
                            + (if $email != "" then {email: $email} else {} end))
                      } else {
                        certificate_path: ($tls + "/fullchain.pem"), key_path: ($tls + "/privkey.pem")
                      } end))
            }]' <<< "$inbounds")"
    fi
    if has shadowtls; then
        inbounds="$(jq -c --arg port "$SHADOWTLS_PORT" --arg name "$NAME" --arg pw "$SHADOWTLS_PASSWORD" \
            --arg sni "$SHADOWTLS_SNI" --arg ss "$SS_PASSWORD" '. + [{
                type: "shadowtls", tag: "shadowtls-in", listen: "::", listen_port: ($port | tonumber),
                version: 3, users: [{name: $name, password: $pw}],
                handshake: {server: $sni, server_port: 443}, strict_mode: true, detour: "ss-in"
            }, {
                type: "shadowsocks", tag: "ss-in", listen: "127.0.0.1", network: "tcp",
                method: "2022-blake3-aes-128-gcm", password: $ss
            }]' <<< "$inbounds")"
    fi
    # Resolve destinations first so the private-address rule also catches
    # hostnames that point at internal or cloud-metadata addresses.
    jq -n --argjson inbounds "$inbounds" '{
        log: {level: "warn", timestamp: true},
        inbounds: $inbounds,
        outbounds: [{type: "direct", tag: "direct"}],
        route: {rules: [
            {action: "resolve"},
            {ip_is_private: true, action: "reject"},
            {ip_cidr: ["0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16"], action: "reject"}
        ], final: "direct"}
    }' > "$TMP/sing-box.json"
    "$NEW_SB" check -c "$TMP/sing-box.json" || die "sing-box rejected the generated configuration"
    install -m 640 -o root -g "$SVC_USER" "$TMP/sing-box.json" "$SB_CONF"
    install -m 755 "$NEW_SB" "$BIN/sing-box"
    write_unit "$SB_SERVICE" "sx-proto sing-box (AnyTLS / ShadowTLS)" "$BIN/sing-box run -c $SB_CONF"
else
    disable_service "$SB_SERVICE"
fi

# ---------- Caddy + forwardproxy: NaïveProxy ----------
if has naive; then
    info "writing Caddy configuration"
    install -d -m 755 -o "$SVC_USER" -g "$SVC_USER" "$WWW"
    if [ ! -f "$WWW/index.html" ]; then
        cat > "$WWW/index.html" <<'EOF'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Welcome</title></head>
<body><h1>Welcome</h1><p>This site is under construction.</p></body></html>
EOF
    fi
    if [ "$CERT_MODE" = builtin ]; then
        # ":PORT" must come first so CONNECT requests for any host reach forward_proxy;
        # "DOMAIN:PORT" makes Caddy obtain and renew the certificate itself.
        site=":$NAIVE_PORT, $DOMAIN:$NAIVE_PORT"; tls_line=""
        email_line=""; [ -z "$EMAIL" ] || email_line="	email $EMAIL"
    else
        site=":$NAIVE_PORT"; tls_line="	tls $TLS_DIR/fullchain.pem $TLS_DIR/privkey.pem"; email_line=""
    fi
    cat > "$TMP/Caddyfile" <<EOF
{
	admin off
	auto_https disable_redirects
$email_line
	order forward_proxy before file_server
	servers {
		protocols h1 h2
	}
	log {
		exclude http.log.error
	}
}

$site {
$tls_line
	forward_proxy {
		basic_auth $NAIVE_USER $NAIVE_PASSWORD
		hide_ip
		hide_via
		probe_resistance
		# forwardproxy already denies loopback and RFC 1918; add the rest.
		acl {
			deny 0.0.0.0/8 100.64.0.0/10 169.254.0.0/16 fc00::/7
		}
	}
	file_server {
		root $WWW
	}
}
EOF
    "$NEW_CADDY" validate --adapter caddyfile --config "$TMP/Caddyfile" >/dev/null 2>"$TMP/caddy-validate.log" \
        || { cat "$TMP/caddy-validate.log" >&2; die "Caddy rejected the generated configuration"; }
    install -m 640 -o root -g "$SVC_USER" "$TMP/Caddyfile" "$CADDYFILE"
    install -m 755 "$NEW_CADDY" "$BIN/caddy"
    write_unit "$NAIVE_SERVICE" "sx-proto NaïveProxy (Caddy forwardproxy)" \
        "$BIN/caddy run --adapter caddyfile --config $CADDYFILE"
else
    disable_service "$NAIVE_SERVICE"
fi

systemctl daemon-reload
STARTED=()
has naive && STARTED+=("$NAIVE_SERVICE")
[ "$NEED_SB" = 1 ] && STARTED+=("$SB_SERVICE")
for svc in "${STARTED[@]}"; do systemctl enable -q "$svc"; systemctl restart "$svc"; done

# ---------- firewall ----------
FW_PORTS=(); for port in "${USED_PORTS[@]}"; do FW_PORTS+=("$port/tcp"); done
{ [ "$CERT_MODE" = certbot ] || [ "$CERT_MODE" = builtin ]; } && FW_PORTS+=(80/tcp)
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep 'Status: active' >/dev/null; then
    for fw_port in "${FW_PORTS[@]}"; do ufw allow "$fw_port" >/dev/null; done
    info "ufw: opened ${FW_PORTS[*]}"
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    for fw_port in "${FW_PORTS[@]}"; do firewall-cmd -q --permanent --add-port="$fw_port"; done
    firewall-cmd -q --reload; info "firewalld: opened ${FW_PORTS[*]}"
fi

# ---------- health checks ----------
info "waiting for the services to listen"
for port in "${USED_PORTS[@]}"; do
    for _ in $(seq 1 30); do [ -n "$(port_owner "$port")" ] && break; sleep 1; done
    [ -n "$(port_owner "$port")" ] || {
        for svc in "${STARTED[@]}"; do journalctl -u "$svc" -n 20 --no-pager >&2; done
        die "nothing is listening on port $port"
    }
done
sleep 1
FAILED=0
TRIES=1; [ "$CERT_MODE" = builtin ] && TRIES=36  # ACME issuance: up to 3 minutes
[ "$TRIES" = 1 ] || info "waiting for the built-in ACME clients to obtain the certificate (up to 3 minutes)"
retry() { # $1 expected output, rest: command; prints the last output
    local i out=""
    for i in $(seq 1 "$TRIES"); do
        out="$("${@:2}" 2>/dev/null || true)"; [ "$out" = "$1" ] && break
        [ "$i" = "$TRIES" ] || sleep 5
    done
    printf '%s' "$out"
}
if has naive; then
    naive_check() { curl -s -o /dev/null --max-time 20 --resolve "$DOMAIN:$NAIVE_PORT:127.0.0.1" "$@" 2>/dev/null || true; }
    naive_tunnel() { printf 'proxy-user = "%s:%s"\n' "$NAIVE_USER" "$NAIVE_PASSWORD" \
        | naive_check -K - --proxy "https://$DOMAIN:$NAIVE_PORT" -w '%{http_code}' "$HEALTH_URL"; }
    code=$(retry 204 naive_tunnel)
    if [ "$code" = 204 ]; then info "naive: authenticated tunnel works"; else warn "naive: tunnel check returned '$code'"; FAILED=1; fi
    code=$(naive_check -w '%{http_code}' "https://$DOMAIN:$NAIVE_PORT/")
    if [ "$code" = 200 ]; then info "naive: unauthenticated visitors see the decoy website"; else warn "naive: decoy site returned '$code'"; FAILED=1; fi
fi
if [ "$NEED_SB" = 1 ]; then
    # Drive the real protocols end to end with a temporary sing-box client on loopback.
    outbounds="[]"; probe_tags=()
    if has anytls; then
        outbounds="$(jq -c --arg port "$ANYTLS_PORT" --arg pw "$ANYTLS_PASSWORD" --arg domain "$DOMAIN" '. + [{
            type: "anytls", tag: "anytls", server: "127.0.0.1", server_port: ($port | tonumber), password: $pw,
            tls: {enabled: true, server_name: $domain}}]' <<< "$outbounds")"
        probe_tags+=(anytls)
    fi
    if has shadowtls; then
        outbounds="$(jq -c --arg port "$SHADOWTLS_PORT" --arg pw "$SHADOWTLS_PASSWORD" --arg sni "$SHADOWTLS_SNI" \
            --arg ss "$SS_PASSWORD" '. + [{
            type: "shadowsocks", tag: "shadowtls", method: "2022-blake3-aes-128-gcm", password: $ss, detour: "shadowtls-tls"
        }, {
            type: "shadowtls", tag: "shadowtls-tls", server: "127.0.0.1", server_port: ($port | tonumber),
            version: 3, password: $pw, tls: {enabled: true, server_name: $sni, utls: {enabled: true, fingerprint: "chrome"}}
        }]' <<< "$outbounds")"
        probe_tags+=(shadowtls)
    fi
    probe_port=$((20000 + RANDOM % 20000))
    inbounds_c="[]"; rules="[]"; i=0
    for tag in "${probe_tags[@]}"; do
        inbounds_c="$(jq -c --arg tag "in-$tag" --argjson port $((probe_port + i)) \
            '. + [{type: "socks", tag: $tag, listen: "127.0.0.1", listen_port: $port}]' <<< "$inbounds_c")"
        rules="$(jq -c --arg in "in-$tag" --arg out "$tag" '. + [{inbound: [$in], outbound: $out}]' <<< "$rules")"
        i=$((i + 1))
    done
    jq -n --argjson ib "$inbounds_c" --argjson ob "$outbounds" --argjson rules "$rules" \
        '{log: {level: "error"}, inbounds: $ib, outbounds: ($ob + [{type: "direct", tag: "direct"}]), route: {rules: $rules, final: "direct"}}' \
        > "$TMP/probe.json"
    "$BIN/sing-box" run -c "$TMP/probe.json" >"$TMP/probe.log" 2>&1 &
    probe_pid=$!
    sleep 2
    i=0
    for tag in "${probe_tags[@]}"; do
        code=$(retry 204 curl -s -o /dev/null --max-time 20 -w '%{http_code}' --socks5-hostname "127.0.0.1:$((probe_port + i))" "$HEALTH_URL")
        if [ "$code" = 204 ]; then info "$tag: end-to-end check through the protocol works"
        else warn "$tag: end-to-end check returned '$code' (journalctl -u $SB_SERVICE)"; FAILED=1; fi
        i=$((i + 1))
    done
    kill "$probe_pid" 2>/dev/null || true; wait "$probe_pid" 2>/dev/null || true
    if has shadowtls; then
        # Without the password, ShadowTLS must look exactly like the borrowed site.
        subject=$(echo | timeout 15 openssl s_client -connect "127.0.0.1:$SHADOWTLS_PORT" -servername "$SHADOWTLS_SNI" 2>/dev/null \
            | openssl x509 -noout -subject 2>/dev/null || true)
        if [ -n "$subject" ]; then info "shadowtls: probes see $SHADOWTLS_SNI's certificate ($subject)"
        else warn "shadowtls: probe did not receive the handshake site's certificate"; FAILED=1; fi
    fi
fi

echo
info "deployed: $PROTOCOLS (ports ${USED_PORTS[*]})"
[ "$FAILED" = 0 ] || warn "some health checks failed; see the warnings above"
echo "Also allow inbound TCP ${USED_PORTS[*]} in your cloud provider's security group if it has one."
echo
show_links
