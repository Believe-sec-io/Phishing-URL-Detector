# 🔎 Phishing URL Detector

A lightweight Python tool for detecting suspicious characteristics in URLs and estimating their phishing risk using static analysis.

> ⚠️ This project is designed for defensive cybersecurity analysis and educational purposes.

## Features

- Analyze URLs locally
- Detect HTTP instead of HTTPS
- Detect IP addresses used as hostnames
- Detect suspicious keywords
- Detect excessive subdomains
- Detect suspicious `@` characters
- Detect excessive hyphens
- Detect unusually long URLs
- Detect unusual special characters
- Detect excessive URL encoding
- Detect large numbers of query parameters
- Calculate a risk score from `0` to `100`
- Classify URLs as:
  - `LOW`
  - `MEDIUM`
  - `HIGH`
- Display detailed indicators
- Works on Windows, Linux and macOS

## Project Structure

```text
phishing-url-detector/
│
├── main.py
├── url_analyzer.py
├── requirements.txt
├── README.md
└── reports/

Requirements

- Python 3.9 or newer
- No external Python packages are currently required

Installation

Clone the repository:

git clone https://github.com/YOUR_USERNAME/phishing-url-detector.git
cd phishing-url-detector

No package installation is required for the current version.

Usage

Run the application:

Windows

python main.py

Linux / macOS

python3 main.py

Enter a URL when prompted:

Enter URL (or 'q' to quit): http://secure-login-example.com/verify/account

Example output:

------------------------------------------------------------
PHISHING URL ANALYSIS
------------------------------------------------------------
URL         : http://secure-login-example.com/verify/account
Protocol    : http
Hostname    : secure-login-example.com
Port        : Default
Path        : /verify/account
------------------------------------------------------------
Risk Score  : 35/100
Risk Level  : LOW
------------------------------------------------------------
Indicators:

[!] URL uses HTTP instead of HTTPS
[!] Suspicious keywords: account, login, verify
------------------------------------------------------------

Risk Scoring

The detector assigns points when suspicious characteristics are identified.

Indicator| Example Score
HTTP instead of HTTPS| +15
IP address as hostname| +25
Long URL| +10
Extremely long URL| +10
"@" character| +20
Excessive subdomains| +15
Many hyphens| +10
Suspicious keywords| Up to +20
Unusual characters| +10
Excessive URL encoding| +10
Many query parameters| +10
Very long domain label| +10

The final score is limited to "100".

Risk Levels

0 - 39    LOW
40 - 69   MEDIUM
70 - 100  HIGH

How It Works

The project performs static URL analysis.

It parses the URL and examines characteristics such as:

URL
 ├── Protocol
 ├── Hostname
 ├── Port
 ├── Path
 ├── Query
 │
 ├── Suspicious keywords
 ├── URL structure
 ├── Special characters
 └── Domain characteristics

The tool does not visit or execute the target website.

Example

A suspicious URL such as:

http://192.168.1.10/secure-login/verify-account

may generate indicators such as:

[!] URL uses HTTP instead of HTTPS
[!] Hostname is an IP address
[!] Suspicious keywords: account, login, secure, verify

Limitations

This tool is a heuristic detector.

A high score does not automatically mean that a URL is malicious, and a low score does not guarantee that a URL is safe.

The current version does not yet perform:

- WHOIS analysis
- DNS reputation checks
- Domain age checks
- Certificate analysis
- Threat intelligence lookups
- VirusTotal integration
- Google Safe Browsing integration
- Machine learning classification

These can be added in future versions.

Roadmap

Version 1.0

- [x] URL parsing
- [x] Static URL analysis
- [x] Suspicious keyword detection
- [x] Risk scoring
- [x] Risk classification
- [x] Terminal interface

Version 1.1

- [ ] Better URL validation
- [ ] Domain reputation analysis
- [ ] DNS analysis
- [ ] WHOIS information
- [ ] Improved domain heuristics

Version 2.0

- [ ] VirusTotal API
- [ ] Google Safe Browsing API
- [ ] JSON reports
- [ ] Batch URL analysis
- [ ] CSV input/output

Future

- [ ] Machine learning model
- [ ] Web dashboard
- [ ] Threat intelligence integration
- [ ] SOC-oriented alerting

Disclaimer

This project is intended for education, cybersecurity research, and defensive security analysis.

Do not use it to interact with or access malicious infrastructure.

License

MIT License
