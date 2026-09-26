# Manual DNS API Provider
# For testing or when automatic DNS management is not available
#

# Provider information
dns_manual_info() {
    echo "Manual DNS API Provider"
    echo "Description: Interactive manual DNS record management"
    echo ""
    echo "WARNING: This provider requires manual interaction and is NOT suitable"
    echo "    for automated certificate renewals (cron jobs, etc.)"
    echo ""
    echo "This provider requires manual intervention to:"
    echo "1. Create TXT records in your DNS provider's control panel"
    echo "2. Verify DNS propagation"
    echo "3. Clean up records after certificate issuance"
    echo ""
    echo "Use Cases:"
    echo "- Testing certificate issuance process"
    echo "- One-time certificate generation"
    echo "- DNS providers not yet supported by automated providers"
    echo "- Learning how DNS-01 challenges work"
    echo ""
    echo "For automated renewals, use providers like:"
    echo "- cloudflare (Cloudflare DNS)"
    echo "- route53 (AWS Route 53)"
    echo "- gcloud (Google Cloud DNS)"
    echo "- azure (Azure DNS)"
    echo "- And others listed in: ./dnsapi/dns_api.sh list"
    echo ""
    echo "Optional Settings:"
    echo "  MANUAL_AUTO_CONTINUE - Skip manual prompts (default: false)"
    echo "  MANUAL_TTL          - Recommended TTL value (default: 120)"
}

# Default settings
MANUAL_TTL=${MANUAL_TTL:-120}
MANUAL_AUTO_CONTINUE=${MANUAL_AUTO_CONTINUE:-false}

# Add TXT record
# Usage: dns_manual_add <domain> <txt_value>
dns_manual_add() {
    domain="$1"
    txt_value="$2"
    record_name="_acme-challenge.$domain"

    dns_log_info "Manual DNS Challenge Setup Required for $domain"
    echo "============================================"
    echo "Manual DNS Challenge Setup Required"
    echo "============================================"
    echo "Domain: $domain"
    echo "Record Type: TXT"
    echo "Record Name: $record_name"
    echo "Record Value: $txt_value"
    echo "TTL: $MANUAL_TTL (seconds)"
    echo ""
    echo "Please create the above TXT record in your DNS provider's control panel."
    echo ""
    echo "Steps:"
    echo "1. Log into your DNS provider's management interface"
    echo "2. Navigate to DNS settings for your domain"
    echo "3. Add a new TXT record with the details above"
    echo "4. Save the changes"
    echo "5. Wait for DNS propagation (usually 1-5 minutes)"
    echo ""

    if [ "$MANUAL_AUTO_CONTINUE" = "true" ]; then
        dns_log_info "Auto-continue mode enabled, proceeding without confirmation"
        return 0
    fi

    echo "Press Enter when the record is created and has propagated..."
    read dummy

    dns_log_info "Verifying DNS propagation..."
    if dns_check_propagation "$domain" "$txt_value" 180 15; then
        dns_log_info "DNS propagation verified successfully"
        return 0
    else
        dns_log_warn "DNS propagation verification failed, but continuing anyway"
        echo ""
        echo "The verification failed, but this might be due to:"
        echo "- DNS propagation delays"
        echo "- Firewall blocking DNS queries"
        echo "- Different DNS resolvers"
        echo ""
        echo "Press Enter to continue anyway, or Ctrl+C to abort..."
        read dummy
        return 0
    fi
}

# Remove TXT record
# Usage: dns_manual_rm <domain> <txt_value>
dns_manual_rm() {
    domain="$1"
    txt_value="$2"
    record_name="_acme-challenge.$domain"

    dns_log_info "Manual DNS Challenge Cleanup for $domain"
    echo "============================================"
    echo "Manual DNS Challenge Cleanup"
    echo "============================================"
    echo "Domain: $domain"
    echo "Record Type: TXT"
    echo "Record Name: $record_name"
    if [ -n "$txt_value" ]; then
        echo "Record Value: $txt_value"
    fi
    echo ""
    echo "You can now remove the TXT record from your DNS provider."
    echo "This is optional as the record is no longer needed."
    echo ""
    if [ "$MANUAL_AUTO_CONTINUE" = "true" ]; then
        dns_log_info "Auto-continue mode enabled, cleanup message displayed"
        return 0
    fi
    echo "Press Enter to continue..."
    read dummy
    return 0
}
