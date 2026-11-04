# DomainScope

A small command-line OSINT utility for collecting basic, publicly available information about a domain.

## Features

- A and AAAA DNS resolution
- MX, NS and TXT records (optional `dnspython`)
- WHOIS registration data (optional `python-whois`)
- HTTPS response status and redirect destination
- TLS certificate details
- JSON report export

## Requirements

- Python 3.9+
- Internet connection
- Optional packages for extended lookups

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/domainscope.git
cd domainscope
python -m pip install -r requirements.txt
```

## Usage

```bash
python domainscope.py example.com
```

Save the output as JSON:

```bash
python domainscope.py example.com --json report.json
```

You can also pass a URL:

```bash
python domainscope.py https://example.com/page
```

## Notes

- DNS, WHOIS and network responses can vary by provider and time.
- Some registrars redact WHOIS information or do not provide all fields.
- MX, NS and TXT lookups require the optional `dnspython` package.
- WHOIS lookup requires the optional `python-whois` package.
- The tool only makes ordinary DNS, HTTPS and WHOIS queries. It does not attempt to log in, bypass access controls, exploit vulnerabilities or scan ports.

## Responsible use

Use DomainScope only for domains you are authorized to investigate or for legitimate research of publicly available information. Respect applicable laws, service terms and rate limits.

## License

MIT
