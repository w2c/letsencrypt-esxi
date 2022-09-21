#!/usr/bin/env python3
# pylint: disable=multiple-imports
"""ACME client to met DNS challenge and receive TLS certificate"""
import argparse, base64, binascii, configparser, copy, hashlib, ipaddress, json, logging
import re, sys, subprocess, time
import requests
import dns.exception, dns.query, dns.name, dns.resolver, dns.rrset, dns.tsigkeyring, dns.update

LOGGER = logging.getLogger('acme_dns_tiny')
LOGGER.addHandler(logging.StreamHandler())


def _base64(text):
    """Encodes string as base64 as specified in the ACME RFC."""
    return base64.urlsafe_b64encode(text).decode("utf8").rstrip("=")


def _openssl(command, options, communicate=None):
    """Run openssl command line and raise IOError on non-zero return."""
    openssl = subprocess.Popen(["openssl", command] + options,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out, err = openssl.communicate(communicate)
    if openssl.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    return out


# pylint: disable=too-many-locals,too-many-branches,too-many-statements
def get_crt(config, log=LOGGER):
    """Get ACME certificate by resolving DNS challenge."""

    def _update_dns(rrset, action, resolver):
        """Updates DNS resource by adding or deleting resource."""
        algorithm = dns.name.from_text("{0}".format(config["TSIGKeyring"]["Algorithm"].lower()))
        dns_update = dns.update.Update(config["DNS"]["zone"],
                                       keyring=private_keyring, keyalgorithm=algorithm)
        if action == "add":
            dns_update.add(rrset.name, rrset)
        elif action == "delete":
            dns_update.delete(rrset.name, rrset)
        # Try each IP address found for the configured DNS Host to apply the DNS resource update
        response = None
        for nameserver in resolver.nameservers:
            try:
                response = dns.query.tcp(dns_update, nameserver,
                                         port=config.getint("DNS", "Port"))
            # pylint: disable=broad-except
            except Exception as exception:
                log.debug("Unable to %s DNS resource on server with IP %s, try again with "
                          "next available IP. Error detail: %s", action, nameserver, exception)
                response = None
            if response is not None:
                break
        if response is None:
            raise RuntimeError("Unable to {0} DNS resource to {1}".format(action, rrset.name))
        return response

    def _send_signed_request(url, payload, extra_headers=None):
        """Sends signed requests to ACME server."""
        nonlocal nonce
        if payload == "":  # on POST-as-GET, final payload has to be just empty string
            payload64 = ""
        else:
            payload64 = _base64(json.dumps(payload).encode("utf8"))
        protected = copy.deepcopy(private_acme_signature)
        protected["nonce"] = nonce or requests.get(acme_config["newNonce"]).headers['Replay-Nonce']
        del nonce
        protected["url"] = url
        if url == acme_config["newAccount"]:
            if "kid" in protected:
                del protected["kid"]
        else:
            del protected["jwk"]
        protected64 = _base64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", config["acmednstiny"]["AccountKeyFile"]],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        jose = {
            "protected": protected64, "payload": payload64, "signature": _base64(signature)
        }
        joseheaders = {'Content-Type': 'application/jose+json'}
        joseheaders.update(adtheaders)
        joseheaders.update(extra_headers or {})
        try:
            response = requests.post(url, json=jose, headers=joseheaders)
        except requests.exceptions.RequestException as error:
            response = error.response
        if response:
            nonce = response.headers['Replay-Nonce']
            try:
                return response, response.json()
            except ValueError:  # if body is empty or not JSON formatted
                return response, json.loads("{}")
        else:
            raise RuntimeError("Unable to get response from ACME server.")

    # main code
    adtheaders = {'User-Agent': 'acme-dns-tiny/2.4',
                  'Accept-Language': config["acmednstiny"].get("Language", "en")}
    nonce = None

    log.info("Find domains to validate from the Certificate Signing Request (CSR) file.")
    csr = _openssl("req", ["-in", config["acmednstiny"]["CSRFile"],
                           "-noout", "-text"]).decode("utf8")
    domains = set()
    common_name = re.search(r"Subject:.*?\s+?CN\s*?=\s*?([^\s,;/]+)", csr)
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(
        r"X509v3 Subject Alternative Name: (?:critical)?\s+([^\r\n]+)\r?\n",
        csr, re.MULTILINE)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    if len(domains) == 0:  # pylint: disable=len-as-condition
        raise ValueError("Didn't find any domain to validate in the provided CSR.")

    log.info("Configure DNS client tools.")
    # That keyring is used to authenticate with the DNS server, it needs to be safely kept
    private_keyring = dns.tsigkeyring.from_text({config["TSIGKeyring"]["KeyName"]:
                                                 config["TSIGKeyring"]["KeyValue"]})
    resolver = dns.resolver.Resolver(configure=False)
    resolver.retry_servfail = True
    nameserver = []
    try:
        ipaddress.ip_address(config["DNS"]["Host"])
        nameserver.append(config["DNS"]["Host"])
    except ValueError:
        log.debug("  - Configured DNS Host value is not a valid IP address, "
                  "try to resolve IP address by requesting system DNS servers.")
        try:
            nameserver += [ipv6_rrset.to_text() for ipv6_rrset
                           in dns.resolver.query(config["DNS"]["Host"], rdtype="AAAA")]
        except dns.exception.DNSException:
            log.debug(("  - IPv6 addresses not found for the configured DNS Host."))
        try:
            nameserver += [ipv4_rrset.to_text() for ipv4_rrset
                           in dns.resolver.query(config["DNS"]["Host"], rdtype="A")]
        except dns.exception.DNSException:
            log.debug("  - IPv4 addresses not found for the configured DNS Host.")
    if not nameserver:
        raise ValueError("Unable to resolve any IP address for the configured DNS Host name")
    resolver.nameservers = nameserver

    log.info("Get private signature from account key.")
    accountkey = _openssl("rsa", ["-in", config["acmednstiny"]["AccountKeyFile"],
                                  "-noout", "-text"])
    signature_search = re.search(r"modulus:\s+?00:([a-f0-9\:\s]+?)\r?\npublicExponent: ([0-9]+)",
                                 accountkey.decode("utf8"), re.MULTILINE)
    if signature_search is None:
        raise ValueError("Unable to retrieve private signature.")
    pub_hex, pub_exp = signature_search.groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    # That signature is used to authenticate with the ACME server, it needs to be safely kept
    private_acme_signature = {
        "alg": "RS256",
        "jwk": {
            "e": _base64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _base64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }
    private_jwk = json.dumps(private_acme_signature["jwk"], sort_keys=True, separators=(",", ":"))
    jwk_thumbprint = _base64(hashlib.sha256(private_jwk.encode("utf8")).digest())

    log.info("Fetch ACME server configuration from the its directory URL.")
    acme_config = requests.get(config["acmednstiny"]["ACMEDirectory"], headers=adtheaders).json()
    terms_service = acme_config.get("meta", {}).get("termsOfService", "")

    log.info("Register ACME Account to get the account identifier.")
    account_request = {}
    if terms_service:
        account_request["termsOfServiceAgreed"] = True
        log.warning(("Terms of service exist and will be automatically agreed if possible, "
                     "you should read them: %s"), terms_service)
    account_request["contact"] = config["acmednstiny"].get("Contacts", "").split(';')
    if account_request["contact"] == [""]:
        del account_request["contact"]

    http_response, account_info = _send_signed_request(acme_config["newAccount"], account_request)
    if http_response.status_code == 201:
        private_acme_signature["kid"] = http_response.headers['Location']
        log.info("  - Registered a new account: '%s'", private_acme_signature["kid"])
    elif http_response.status_code == 200:
        private_acme_signature["kid"] = http_response.headers['Location']
        log.debug("  - Account is already registered: '%s'", private_acme_signature["kid"])

        http_response, account_info = _send_signed_request(private_acme_signature["kid"], "")
    else:
        raise ValueError("Error registering account: {0} {1}"
                         .format(http_response.status_code, account_info))

    log.info("Update contact information if needed.")
    if ("contact" in account_request
            and set(account_request["contact"]) != set(account_info["contact"])):
        http_response, result = _send_signed_request(private_acme_signature["kid"],
                                                     account_request)
        if http_response.status_code == 200:
            log.debug("  - Account updated with latest contact informations.")
        else:
            raise ValueError("Error registering updates for the account: {0} {1}"
                             .format(http_response.status_code, result))

    # new order
    log.info("Request to the ACME server an order to validate domains.")
    new_order = {"identifiers": [{"type": "dns", "value": domain} for domain in domains]}
    http_response, order = _send_signed_request(acme_config["newOrder"], new_order)
    if http_response.status_code == 201:
        order_location = http_response.headers['Location']
        log.debug("  - Order received: %s", order_location)
        if order["status"] != "pending" and order["status"] != "ready":
            raise ValueError("Order status is neither pending neither ready, we can't use it: {0}"
                             .format(order))
    elif (http_response.status_code == 403
          and order["type"] == "urn:ietf:params:acme:error:userActionRequired"):
        raise ValueError(("Order creation failed ({0}). Read Terms of Service ({1}), then follow "
                          "your CA instructions: {2}")
                         .format(order["detail"],
                                 http_response.headers['Link'], order["instance"]))
    else:
        raise ValueError("Error getting new Order: {0} {1}"
                         .format(http_response.status_code, order))

    # complete each authorization challenge
    for authz in order["authorizations"]:
        if order["status"] == "ready":
            log.info("No challenge to process: order is already ready.")
            break

        log.info("Process challenge for authorization: %s", authz)
        # get new challenge
        http_response, authorization = _send_signed_request(authz, "")
        if http_response.status_code != 200:
            raise ValueError("Error fetching challenges: {0} {1}"
                             .format(http_response.status_code, authorization))
        domain = authorization["identifier"]["value"]

        if authorization["status"] == "valid":
            log.info("Skip authorization for domain %s: this is already validated", domain)
            continue
        if authorization["status"] != "pending":
            raise ValueError("Authorization for the domain {0} can't be validated: "
                             "the authorization is {1}.".format(domain, authorization["status"]))

        challenges = [c for c in authorization["challenges"] if c["type"] == "dns-01"]
        if not challenges:
            raise ValueError("Unable to find a DNS challenge to resolve for domain {0}"
                             .format(domain))
        log.info("Install DNS TXT resource for domain: %s", domain)
        challenge = challenges[0]
        keyauthorization = challenge["token"] + "." + jwk_thumbprint
        keydigest64 = _base64(hashlib.sha256(keyauthorization.encode("utf8")).digest())
        dnsrr_domain = "_acme-challenge.{0}.".format(domain)
        try:  # a CNAME resource can be used for advanced TSIG configuration
            # Note: the CNAME target has to be of "non-CNAME" type (recursion isn't managed)
            dnsrr_domain = [response.to_text() for response
                            in resolver.query(dnsrr_domain, rdtype="CNAME")][0]
            log.info("  - A CNAME resource has been found for this domain, will install TXT on %s",
                     dnsrr_domain)
        except dns.exception.DNSException as dnsexception:
            log.debug(("  - No CNAME resource has been found for this domain (%s), will "
                       "install TXT directly on %s"), type(dnsexception).__name__, dnsrr_domain)
        dnsrr_set = dns.rrset.from_text(dnsrr_domain, config["DNS"].getint("TTL"),
                                        "IN", "TXT", '"{0}"'.format(keydigest64))
        try:
            _update_dns(dnsrr_set, "add", resolver)
        except dns.exception.DNSException as exception:
            raise ValueError("Error updating DNS records: {0} : {1}"
                             .format(type(exception).__name__, str(exception))) from exception

        log.info("Wait for 1 TTL (%s seconds) to ensure DNS cache is cleared.",
                 config["DNS"].getint("TTL"))
        time.sleep(config["DNS"].getint("TTL"))
        challenge_verified = False
        number_check_fail = 1
        while challenge_verified is False:
            try:
                log.debug(('Self test (try: %s): Check resource with value "%s" exits on '
                           'nameservers: %s'), number_check_fail, keydigest64,
                          resolver.nameservers)
                for response in resolver.query(dnsrr_domain, rdtype="TXT").rrset:
                    log.debug("  - Found value %s", response.to_text())
                    challenge_verified = (challenge_verified
                                          or response.to_text() == '"{0}"'.format(keydigest64))
            except dns.exception.DNSException as dnsexception:
                log.debug(
                    "  - Will retry as a DNS error occurred while checking challenge: %s : %s",
                    type(dnsexception).__name__, dnsexception)
            finally:
                if challenge_verified is False:
                    if number_check_fail >= 10:
                        raise ValueError("Error checking challenge, value not found: {0}"
                                         .format(keydigest64))
                    number_check_fail = number_check_fail + 1
                    time.sleep(config["DNS"].getint("TTL"))

        log.info("Asking ACME server to validate challenge.")
        http_response, result = _send_signed_request(challenge["url"], {})
        if http_response.status_code != 200:
            raise ValueError("Error triggering challenge: {0} {1}"
                             .format(http_response.status_code, result))
        try:
            while True:
                http_response, challenge_status = _send_signed_request(challenge["url"], "")
                if http_response.status_code != 200:
                    raise ValueError("Error during challenge validation: {0} {1}".format(
                        http_response.status_code, challenge_status))
                if challenge_status["status"] == "pending":
                    time.sleep(2)
                elif challenge_status["status"] == "valid":
                    log.info("ACME has verified challenge for domain: %s", domain)
                    break
                else:
                    raise ValueError("Challenge for domain {0} did not pass: {1}".format(
                        domain, challenge_status))
        finally:
            _update_dns(dnsrr_set, "delete", resolver)

    log.info("Request to finalize the order (all challenges have been completed)")
    csr_der = _base64(_openssl("req", ["-in", config["acmednstiny"]["CSRFile"],
                                       "-outform", "DER"]))
    http_response, result = _send_signed_request(order["finalize"], {"csr": csr_der})
    if http_response.status_code != 200:
        raise ValueError("Error while sending the CSR: {0} {1}"
                         .format(http_response.status_code, result))

    while True:
        http_response, order = _send_signed_request(order_location, "")

        if order["status"] == "processing":
            try:
                time.sleep(float(http_response.headers["Retry-After"]))
            except (OverflowError, ValueError, TypeError):
                time.sleep(2)
        elif order["status"] == "valid":
            log.info("Order finalized!")
            break
        else:
            raise ValueError("Finalizing order {0} got errors: {1}".format(
                order_location, order))

    http_response, result = _send_signed_request(
        order["certificate"], "",
        {'Accept': config["acmednstiny"].get("CertificateFormat",
                                             'application/pem-certificate-chain')})
    if http_response.status_code != 200:
        raise ValueError("Finalizing order {0} got errors: {1}"
                         .format(http_response.status_code, result))

    if 'link' in http_response.headers:
        log.info("  - Certificate links given by server: %s", http_response.headers['link'])

    log.info("Certificate signed and chain received: %s", order["certificate"])
    return http_response.text


def main(argv):
    """Parse arguments and get certificate."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Tiny ACME client to get TLS certificate by responding to DNS challenges.",
        epilog="""As the script requires access to your private ACME account key and dns server,
so PLEASE READ THROUGH IT (it won't take too long, it's a one-file script) !

Example: requests certificate chain and store it in chain.crt
  python3 acme_dns_tiny.py ./example.ini > chain.crt

See example.ini file to configure correctly this script."""
    )
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR,
                        help="show only errors on stderr")
    parser.add_argument("--verbose", action="store_const", const=logging.DEBUG,
                        help="show all debug informations on stderr")
    parser.add_argument("--csr",
                        help="specifies CSR file path to use instead of the CSRFile option \
from the configuration file.")
    parser.add_argument("configfile", help="path to your configuration file")
    args = parser.parse_args(argv)

    config = configparser.ConfigParser()
    config.read_dict({
        "acmednstiny": {"ACMEDirectory": "https://acme-staging-v02.api.letsencrypt.org/directory"},
        "DNS": {"Port": 53, "TTL": 10}})
    config.read(args.configfile)

    if args.csr:
        config.set("acmednstiny", "csrfile", args.csr)

    if (set(["accountkeyfile", "csrfile", "acmedirectory"]) - set(config.options("acmednstiny"))
            or set(["keyname", "keyvalue", "algorithm"]) - set(config.options("TSIGKeyring"))
            or set(["zone", "host", "port", "ttl"]) - set(config.options("DNS"))):
        raise ValueError("Some required settings are missing.")

    LOGGER.setLevel(args.verbose or args.quiet or logging.INFO)
    signed_crt = get_crt(config, LOGGER)
    sys.stdout.write(signed_crt)


if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
