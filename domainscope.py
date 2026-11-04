#!/usr/bin/env python3
"""DomainScope: collect basic, publicly available domain information."""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def normalize_domain(value: str) -> str:
    value = value.strip()
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/")[0].split(":")[0].rstrip(".").lower()
    if not value or len(value) > 253 or "." not in value:
        raise ValueError("Enter a valid domain, e.g. example.com")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain name") from exc
    labels = value.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
           or not all(c.isalnum() or c == "-" for c in label) for label in labels):
        raise ValueError("Invalid domain format")
    return value


def resolve_addresses(domain):
    result = {"A": [], "AAAA": []}
    for family, key in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
        try:
            for item in socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM):
                result[key].append(item[4][0])
        except socket.gaierror:
            pass
        result[key] = sorted(set(result[key]))
    return result


def resolve_extra_dns(domain):
    result = {"MX": [], "NS": [], "TXT": []}
    try:
        import dns.resolver
    except ImportError:
        return {"available": False, "note": "Install dnspython to query MX, NS and TXT records."}

    for record_type in ("MX", "NS", "TXT"):
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=4)
            result[record_type] = sorted(str(answer).strip('"') for answer in answers)
        except Exception:
            result[record_type] = []
    result["available"] = True
    return result


def get_whois(domain):
    try:
        import whois
    except ImportError:
        return {"available": False, "note": "Install python-whois to enable WHOIS lookup."}

    try:
        data = whois.whois(domain)
        fields = ("registrar", "creation_date", "expiration_date", "updated_date",
                  "name_servers", "status", "country")
        output = {"available": True}
        for field in fields:
            value = getattr(data, field, None)
            if isinstance(value, list):
                value = [str(item) for item in value]
            elif value is not None:
                value = str(value)
            if value:
                output[field] = value
        return output
    except Exception as exc:
        return {"available": True, "error": str(exc)}


def check_http(domain):
    url = f"https://{domain}"
    request = Request(url, headers={"User-Agent": "DomainScope/1.0"})
    try:
        with urlopen(request, timeout=7) as response:
            return {
                "url": url,
                "status": response.status,
                "final_url": response.geturl(),
                "server": response.headers.get("Server"),
                "content_type": response.headers.get("Content-Type"),
            }
    except HTTPError as exc:
        return {"url": url, "status": exc.code, "final_url": exc.geturl()}
    except (URLError, TimeoutError, OSError) as exc:
        return {"url": url, "error": str(exc)}


def get_tls_certificate(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "subject_alt_names": [value for kind, value in cert.get("subjectAltName", [])
                                  if kind == "DNS"][:30],
        }
    except (OSError, ssl.SSLError) as exc:
        return {"error": str(exc)}


def main():
    parser = argparse.ArgumentParser(
        description="Collect basic public DNS, WHOIS, HTTP and TLS information for a domain."
    )
    parser.add_argument("domain", help="Domain name, e.g. example.com")
    parser.add_argument("--json", dest="json_file", help="Save results to a JSON file")
    args = parser.parse_args()

    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        parser.error(str(exc))

    report = {
        "tool": "DomainScope",
        "version": "1.0.0",
        "domain": domain,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "dns_addresses": resolve_addresses(domain),
        "dns_records": resolve_extra_dns(domain),
        "whois": get_whois(domain),
        "http": check_http(domain),
        "tls": get_tls_certificate(domain),
    }

    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    if args.json_file:
        with open(args.json_file, "w", encoding="utf-8") as file:
            json.dump(report, file, ensure_ascii=False, indent=2, default=str)
        print(f"\n[+] Report saved to {args.json_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
