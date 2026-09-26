#!/bin/sh
#
# Copyright (c) Johannes Feichtner <johannes@web-wack.at>
# Released under the GNU GPLv3 License.

DOMAIN=$(hostname -f)
LOCALDIR=$(dirname "$(readlink -f "$0")")
LOCALSCRIPT=$(basename "$0")

ACMEDIR="$LOCALDIR/.well-known/acme-challenge"
DIRECTORY_URL="https://acme-v02.api.letsencrypt.org/directory"
SSL_CERT_FILE="$LOCALDIR/ca-certificates.crt"
RENEW_DAYS=30

ACCOUNTKEY="esxi_account.key"
KEY="esxi.key"
CSR="esxi.csr"
CRT="esxi.crt"
VMWARE_CRT="/etc/vmware/ssl/rui.crt"
VMWARE_KEY="/etc/vmware/ssl/rui.key"

# Default to HTTP-01 challenge
CHALLENGE_TYPE="http-01"
DNS_PROVIDER=""
DNS_PROPAGATION_WAIT=30

# Load user configuration (if available)
if [ -r "$LOCALDIR/renew.cfg" ]; then
  . "$LOCALDIR/renew.cfg"
fi

# Export configuration variables
export CHALLENGE_TYPE DNS_PROVIDER DNS_PROPAGATION_WAIT \
  CF_API_TOKEN CF_API_KEY CF_EMAIL \
  DIRECTORY_URL CONTACT_EMAIL \
  ACCOUNTKEY KEY CSR CRT VMWARE_CRT VMWARE_KEY SSL_CERT_FILE

log() {
   echo "$@"
   logger -p daemon.info -t "$0" "$@"
}

log "Starting certificate renewal.";

# Preparation steps
if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "${DOMAIN/.}" ]; then
  log "Error: Hostname ${DOMAIN} is no FQDN."
  exit
fi

# Add a cronjob for auto renewal. The script is run once a week on Sunday at 00:00
if ! grep -q "$LOCALDIR/$LOCALSCRIPT" /var/spool/cron/crontabs/root; then
  kill -sighup "$(pidof crond)" 2>/dev/null
  echo "0    0    *   *   0   /bin/sh $LOCALDIR/$LOCALSCRIPT" >> /var/spool/cron/crontabs/root
  crond
fi

# Check issuer and expiration date of existing cert
if [ -e "$VMWARE_CRT" ]; then
  # If the cert is issued for a different hostname, request a new one
  SAN=$(openssl x509 -in "$VMWARE_CRT" -text -noout | grep DNS: | sed 's/DNS://g' | xargs)
  if [ "$SAN" != "$DOMAIN" ] ; then
    log "Existing cert issued for ${SAN} but current domain name is ${DOMAIN}. Requesting a new one!"
  # If the cert is issued by Let's Encrypt, check its expiration date, otherwise request a new one
  elif openssl x509 -in "$VMWARE_CRT" -issuer -noout | grep -qE "O ?= ?Let's Encrypt"; then
    CERT_VALID=$(openssl x509 -enddate -noout -in "$VMWARE_CRT" | cut -d= -f2-)
    log "Existing Let's Encrypt cert valid until: ${CERT_VALID}"
    if openssl x509 -checkend $((RENEW_DAYS * 86400)) -noout -in "$VMWARE_CRT"; then
      log "=> Longer than ${RENEW_DAYS} days. Aborting."
      exit
    else
      log "=> Less than ${RENEW_DAYS} days. Renewing!"
    fi
  else
    log "Existing cert for ${DOMAIN} not issued by Let's Encrypt. Requesting a new one!"
  fi
fi

cd "$LOCALDIR" || exit

# Detect if we're running in an automated context (cron, etc.)
is_automated_run() {
    if [ ! -t 0 ]; then return 0; fi
    if [ -z "$TERM" ] || [ "$TERM" = "dumb" ]; then return 0; fi
    if [ -n "$CRON" ]; then return 0; fi
    if ps -o comm= -p $PPID 2>/dev/null | grep -q "crond"; then return 0; fi
    return 1
}

# Cleanup function to restore firewall rules
cleanup_firewall() {
  if [ "$CHALLENGE_TYPE" = "http-01" ]; then
    # Kill HTTP server if still running
    if [ -n "$HTTP_SERVER_PID" ]; then
      kill -9 "$HTTP_SERVER_PID" 2>/dev/null || true
    fi
    # Restore original firewall states
    if [ -n "$ORIGINAL_WEBACCESS_STATE" ] && [ "$ORIGINAL_WEBACCESS_STATE" = "false" ]; then
      esxcli network firewall ruleset set -e false -r webAccess 2>/dev/null || true
      log "Restored webAccess firewall rule to disabled"
    fi
    if [ -n "$ORIGINAL_VSPHERE_STATE" ] && [ "$ORIGINAL_VSPHERE_STATE" = "false" ]; then
      esxcli network firewall ruleset set -e false -r vSphereClient 2>/dev/null || true
      log "Restored vSphereClient firewall rule to disabled"
    fi
  elif [ "$CHALLENGE_TYPE" = "dns-01" ]; then
    # Restore original httpClient state
    if [ -n "$ORIGINAL_HTTPCLIENT_STATE" ] && [ "$ORIGINAL_HTTPCLIENT_STATE" = "false" ]; then
      esxcli network firewall ruleset set -e false -r httpClient 2>/dev/null || true
      log "Restored httpClient firewall rule to disabled"
    fi
  fi
}

trap cleanup_firewall EXIT INT TERM

# Helper to enable outbound ACME firewall rule and store state
enable_httpclient_firewall() {
  httpclient_enabled=$(esxcli network firewall ruleset list | grep "httpClient" | awk '{print $NF}')
  ORIGINAL_HTTPCLIENT_STATE="$httpclient_enabled"
  if [ "$httpclient_enabled" = "false" ]; then
    esxcli network firewall ruleset set -e true -r httpClient
    log "Enabled httpClient firewall rule for ACME communication"
  fi
}

# Setup based on challenge type
if [ "$CHALLENGE_TYPE" = "http-01" ]; then
  mkdir -p "$ACMEDIR"

  # Route /.well-known/acme-challenge to port 8120
  if ! grep -q "acme-challenge" /etc/vmware/rhttpproxy/endpoints.conf; then
    echo "/.well-known/acme-challenge local 8120 redirect allow" >> /etc/vmware/rhttpproxy/endpoints.conf
    /etc/init.d/rhttpproxy restart
  fi

  # Firewall management for HTTP-01 (needs inbound access on port 80/443)
  log "Configuring firewall for HTTP-01 challenge..."
  firewall_enabled=$(esxcli network firewall get | grep "Enabled:" | awk '{print $NF}')
  webaccess_enabled=$(esxcli network firewall ruleset list | grep "webAccess" | awk '{print $NF}')
  vsphere_enabled=$(esxcli network firewall ruleset list | grep "vSphereClient" | awk '{print $NF}')
  # Store original states for restoration
  ORIGINAL_FIREWALL_STATE="$firewall_enabled"
  ORIGINAL_WEBACCESS_STATE="$webaccess_enabled"
  ORIGINAL_VSPHERE_STATE="$vsphere_enabled"
  # Enable required rulesets for HTTP-01
  if [ "$webaccess_enabled" = "false" ]; then
    esxcli network firewall ruleset set -e true -r webAccess
    log "Enabled webAccess firewall rule for HTTP-01"
  fi
  if [ "$vsphere_enabled" = "false" ]; then
    esxcli network firewall ruleset set -e true -r vSphereClient
    log "Enabled vSphereClient firewall rule for HTTP-01"
  fi
  # Enable outbound HTTP client for ACME communication (consolidated)
  enable_httpclient_firewall
  # Start HTTP server on port 8120 for HTTP validation
  python3 -m "http.server" 8120 &
  HTTP_SERVER_PID=$!

elif [ "$CHALLENGE_TYPE" = "dns-01" ]; then
  # Validate DNS provider configuration for DNS-01 challenge
  if [ -z "$DNS_PROVIDER" ]; then
    log "Error: DNS_PROVIDER must be set for dns-01 challenge"
    exit 1
  fi
  # Prevent automated renewal with manual DNS provider
  if [ "$DNS_PROVIDER" = "manual" ]; then
    if is_automated_run; then
      log "Manual DNS provider detected in automated context (likely cron job)."
      log "Skipping renewal to prevent user interaction requirements."
      log "Manual DNS certificates should be renewed manually by running:"
      log "  $LOCALDIR/$LOCALSCRIPT"
      log "Or change DNS_PROVIDER to an automated provider in renew.cfg"
      exit 0
    else
      log "Manual DNS provider detected. This will require interactive input."
      log "Press Ctrl+C now if you want to cancel and switch to an automated provider."
      sleep 3
    fi
  fi
  # Ensure DNS API script is present and executable
  if [ ! -x "$LOCALDIR/dnsapi/dns_api.sh" ]; then
    log "Error: DNS API script not found or not executable: $LOCALDIR/dnsapi/dns_api.sh"
    exit 1
  fi
  # Only outbound firewall access is needed for DNS-01
  log "Configuring firewall for DNS-01 challenge..."
  enable_httpclient_firewall
  log "Using DNS provider: $DNS_PROVIDER"
fi

# Cert Request (consolidated)
acme_args="--account-key \"$ACCOUNTKEY\" --csr \"$CSR\" --directory-url \"$DIRECTORY_URL\" --challenge-type \"$CHALLENGE_TYPE\""
if [ "$CHALLENGE_TYPE" = "http-01" ]; then
  acme_args="$acme_args --acme-dir \"$ACMEDIR\""
fi
CERT=$(eval python ./acme_tiny.py $acme_args 2>acme_error.log)
[ "$CHALLENGE_TYPE" = "http-01" ] && [ -n "$HTTP_SERVER_PID" ] && kill -9 "$HTTP_SERVER_PID"

# If an error occurred during certificate issuance, $CERT will be empty
if [ -n "$CERT" ] ; then
  echo "$CERT" > "$CRT"
  # Provide the certificate to ESXi
  cp -p "$LOCALDIR/$KEY" "$VMWARE_KEY"
  cp -p "$LOCALDIR/$CRT" "$VMWARE_CRT"
  log "Success: Obtained and installed a certificate from Let's Encrypt."
elif openssl x509 -checkend 86400 -noout -in "$VMWARE_CRT"; then
  log "Warning: No cert obtained from Let's Encrypt. Keeping the existing one as it is still valid."
else
  log "Error: No cert obtained from Let's Encrypt. Generating a self-signed certificate."
  /sbin/generate-certificates
fi

for s in /etc/init.d/*; do if $s | grep ssl_reset > /dev/null; then $s ssl_reset; fi; done
