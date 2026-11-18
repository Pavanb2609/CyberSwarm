# CyberSwarm — Tools Reference

All tools, their capabilities, exact commands, install instructions, and known issues.

---

## Phase 1 — Recon Tools (26 capabilities)

### Passive Recon

#### `subfinder` — SUBDOMAIN_DISCOVERY

# Command used internally
subfinder -d <target> -silent -oJ



#### `amass` — PASSIVE_ASSET_DISCOVERY

# Command used internally
amass enum -passive -d <target> -json /tmp/<target>.json



### DNS

#### `dns_resolve` — DNS_RESOLUTION
```
No external binary. Uses Python dnspython library.
pip install dnspython

# Resolves A, AAAA, MX, NS, TXT, CNAME records for the target.
```

#### `dns_enum` — DNS_ENUMERATION
```
No external binary. Uses Python dnspython library.
pip install dnspython

# Attempts zone transfer + common record enumeration.
```
# Will be taking the best tool according to the testcase
---

### Port Scanning

#### `nmap` — HOST_DISCOVERY


# Command used internally
nmap -sn -oX /tmp/<target>.xml <target>

#### `naabu` — PORT_DISCOVERY

# Command used internally
naabu -host <target> -top-ports 1000 -silent -json



#### `nmap` — SERVICE_DETECTION

# Command used internally
nmap -sV -oX /tmp/<target>.xml -p <open_ports> <target>



#### `nmap` — OPERATING_SYSTEM_IDENTIFICATION

# Command used internally (requires sudo)
nmap -O -oX /tmp/<target>.xml <target> -- will be authorized by us 

---

### Web Probing

#### `httpx` — WEB_PROBING

# Command used internally
httpx -u <target> -silent -json -title -status-code -tech-detect


#### `whatweb` — WEB_TECHNOLOGY_DISCOVERY


# Command used internally
whatweb --log-json=- --no-errors <url>


#### `header_analysis` — HEADER_ANALYSIS
```
No external binary. pure python (urllib + ssl).
Fetches HTTP headers and checks for missing security headers:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
```

---

### TLS

#### `testssl.sh` — TLS_ANALYSIS (preferred)

```bash
# Install testssl.sh
git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl
sudo ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl

# testssl.sh is a standalone bash script — no compilation needed
# It bundles its own OpenSSL binary for testing

# Command used internally (full scan mode)
testssl --jsonfile-pretty /tmp/<target>_testssl.json \
        --warnings batch --color 0 --quiet \
        <target>:443

# Command used internally (vulnerability-only mode, Phase 2)
testssl --jsonfile-pretty /tmp/<target>_testssl.json \
        --vulnerabilities --severity MEDIUM \
        --warnings batch --color 0 --quiet \
        <target>:443

# Manual equivalent
testssl <target>:443

# Vulnerability-only scan
testssl --vulnerabilities --severity MEDIUM <target>:443

# Specific checks
testssl --heartbleed <target>:443
testssl --poodle <target>:443
testssl --drown <target>:443
testssl --robot <target>:443
testssl --sweet32 <target>:443

# Full scan with HTML output
testssl --html <target>:443
```

#### `openssl` — TLS_ANALYSIS (fallback)

```
# Only used if testssl.sh is not installed
openssl s_client -connect <target>:443 -servername <target>
```

---

### Web Crawling & Discovery

#### `katana` — WEB_CRAWLING


# Command used internally
katana -u <url> -silent -jsonl -depth 3



#### `ffuf` — CONTENT_DISCOVERY


# Command used internally
ffuf -u <url>/FUZZ -w /usr/share/wordlists/dirb/common.txt \
     -mc 200,204,301,302,307,401,403 -of json -o /tmp/<target>_ffuf.json \
     -t 40 -timeout 10

# wordlist 

---our own wordlist 


#### `gau` / `waybackurls` — HISTORICAL_URL_DISCOVERY


# Command used internally (gau first, waybackurls as fallback)
gau <target>
waybackurls <target>



---

### JavaScript & Parameters

#### `linkfinder` — JAVASCRIPT_ANALYSIS

# Command used internally
linkfinder -i <url> -d -o cli

# Manual equivalent
linkfinder -i https://sandbox.securegateway.com -d -o cli


#### `arjun` — PARAMETER_DISCOVERY


# Command used internally
arjun -u <url> -oJ /tmp/<target>_arjun.json

---

### CMS

#### `cms_identify` — CMS_IDENTIFICATION

No external binary. Pure Python (requests).
Checks HTTP response body and headers for signatures of:
  WordPress, Joomla, Drupal, Magento, Ghost, Shopify, Wix, Squarespace


#### `wpscan` — CMS_ASSESSMENT


# Command used internally (only runs if WordPress detected)
wpscan --url <url> --no-banner --random-user-agent \
       --enumerate p,t,u --format json --output /tmp/<target>_wpscan.json



---

### Screenshots


# Command used internally
gowitness scan file --file /tmp/<target>_urls.txt \
    --write-db --screenshot-path results/screenshots/<target>/



---

### Cloud, Container, IoT

#### `cloud_enum` — CLOUD_ASSET_DISCOVERY
```
No external binary. Pure Python (requests).
Only runs if Cloud-provider signals detected in technologies/headers.
Checks: AWS S3 buckets, GCP storage, Azure blobs using target name permutations.
```

#### `container_probe` — CONTAINER_DISCOVERY
```
No external binary. Pure Python (requests + sockets).
Only runs if container-platform ports detected (2375, 2376, 4243, 8080).
Checks: Docker API, Kubernetes API, Portainer.
```

#### `iot_probe` — IOT_SERVICE_IDENTIFICATION
```
No external binary. Pure Python (sockets).
Only runs if IoT-related ports open (1883 MQTT, 5683 CoAP, 1900 UPnP).
Checks: MQTT broker, CoAP endpoint, UPnP SSDP.



### Directory Services

#### `ldap_enum` — DIRECTORY_SERVICE_ENUMERATION

# Requires ldap3 Python library
pip install ldap3

# Only runs if LDAP/Kerberos ports open (389, 636, 3268, 88).
# Attempts anonymous bind and base DN enumeration.
```

#### `smb_enum` — WINDOWS_SERVICE_ENUMERATION  (uses nmap)
```bash
# Requires nmap (already installed for port scanning)

# Command used internally (only runs if 139/445 open)
nmap -p 139,445 --script smb-security-mode,smb-enum-shares,smb2-security-mode \
     --script-timeout 30s -oX /tmp/<target>_smb.xml <target>

# Manual equivalent
nmap -p 139,445 --script smb-security-mode,smb-enum-shares \
     sandbox.securegateway.com
```

#### `api_discover` — API_ENDPOINT_DISCOVERY
```
No external binary. Pure Python (requests).
Probes common API paths: /api, /api/v1, /graphql, /swagger, /openapi.json,
/rest, /v1, /v2, /.well-known/openid-configuration, etc.  ------ need to be added and create a wordlist 
```

---

## Phase 2 — Attack Tools (26 capabilities)

### `nuclei` — VULN_SCAN



# Command used internally
nuclei -u <url> \
       -o /tmp/<target>.jsonl \
       -jsonl \
       -severity low,medium,high,critical \
       -silent \
       -timeout 10 \
       -retries 1 \
       -rate-limit 50 \
       -etags intrusive,dos,fuzz \
       [-tags <tags>]

# Manual equivalent — general scan
nuclei -u https://sandbox.securegateway.com -severity medium,high,critical -silent

# With tags (focused)
nuclei -u https://sandbox.securegateway.com -tags headers,misconfig,ssl -silent

# With tags for CMS
nuclei -u https://sandbox.securegateway.com -tags wordpress,cms -silent
```



---

### `nikto` — WEB_VULN_SCAN


# Command used internally
nikto -h <url> \
      -o /tmp/<target>_nikto.json \
      -Format json \
      -nointeractive \
      -maxtime 240 \
      -Tuning x6



# Tuning flags:
#   x = skip DoS tests
#   6 = misconfiguration checks
```

---

### `nmap` — SERVICE_VULN_SCAN
```bash
# Install
sudo apt install nmap

# Command used internally
nmap -sV \
     --script vuln \
     --script-timeout 60s \
     -T4 \
     --open \
     -p <ports_or_default> \
     <target>


---

### `testssl.sh` — TLS_VULN_SCAN

```bash
# Same install as Phase 1 (testssl.sh handles both recon and vuln scanning)

# Command used internally (vulnerability-focused, severity-filtered)
testssl --jsonfile-pretty /tmp/<target>_testssl_vuln.json \
        --vulnerabilities --severity MEDIUM \
        --warnings batch --color 0 --quiet \
        <target>:443

# Manual equivalent
testssl --vulnerabilities --severity MEDIUM <target>:443

# Checks included: Heartbleed, CCS Injection, Ticketbleed, ROBOT,
# POODLE, DROWN, FREAK, LOGJAM, BEAST, LUCKY13, SWEET32, RC4,
# CRIME, BREACH, TLS_FALLBACK_SCSV, Winshock, Renegotiation
```

---

### `searchsploit` — EXPLOIT_SEARCH

# After install, update the local DB:
searchsploit -u

# Command used internally (one call per technology)
searchsploit --json --exclude dos "<technology> <version>"

# Manual equivalent
searchsploit --json --exclude dos "nginx 1.26"
searchsploit --json --exclude dos "Apache httpd 2.4.7"
searchsploit --json --exclude dos "WordPress 5.8"
searchsploit --json --exclude dos "OpenSSH 6.6"
```

---

## Expanded Phase 2 — Additional Attack Tools

### Nuclei tag-driven wrappers (SSRF / LFI / SSTI / redirect / CMDi / XSS / SQLi / panels / default-logins / misconfig / takeover / host-header / clickjacking / exposure / waf-detect)

One parameterized wrapper (`tools/attack/nuclei_tags.py`) pins a `capability` +
default `-tags` set per action; parses JSONL exactly like `NucleiTool`:

```bash
# internal: nuclei -u <url> -tags <tagset> -jsonl -severity low,medium,high,critical -silent
nuclei -u https://target -tags ssrf -jsonl -silent
nuclei -u https://target -tags lfi -jsonl -silent
nuclei -u https://target -tags ssti -jsonl -silent
nuclei -u https://target -tags redirect -jsonl -silent
nuclei -u https://target -tags command-injection -jsonl -silent
nuclei -u https://target -tags exposed-panels -jsonl -silent
nuclei -u https://target -tags default-login -jsonl -silent
nuclei -u https://target -tags misconfig -jsonl -silent
nuclei -u https://target -tags takeover -jsonl -silent
nuclei -u https://target -tags host-header -jsonl -silent
nuclei -u https://target -tags clickjacking -jsonl -silent
nuclei -u https://target -tags exposure,secrets -jsonl -silent
nuclei -u https://target -tags waf-detect -jsonl -silent
```

### `wafw00f` — WAF_DETECT
```bash
# Install
pip install --break-system-packages wafw00f

# internal: wafw00f -a -o <tmp>.json -f json <url>
wafw00f -a -o /tmp/waf.json -f json https://target
```

### `sslyze` — TLS_VULN_SCAN (fallback to testssl)
```bash
# Install
pip install --break-system-packages sslyze

# internal: sslyze --json_out <tmp>.json --quiet --heartbleed --robot --compression --reneg --resum <host>
sslyze --json_out /tmp/tls.json --quiet --heartbleed --robot --compression --reneg --resum example.com:443
```

### `subjack` — SUBDOMAIN_TAKEOVER_SCAN (fallback to nuclei takeover)
```bash
# Install
go install github.com/haccer/subjack@latest

# internal: subjack -d <domain> -o <tmp>.txt -a
subjack -d example.com -o /tmp/takeover.txt -a
```

### `commix` — CMD_INJECTION_SCAN (fallback to nuclei command-injection)
```bash
# Install
git clone https://github.com/commixproject/commix && ln -sf $PWD/commix/commix.py ~/.local/bin/commix

# internal: commix --url <url> --level 1 --batch
commix --url https://target/page?id=1 --level 1 --batch
```

### `jwt_tool` — JWT_ANALYSIS (stateless checks only; no brute force)
```bash
# Install
git clone https://github.com/ticarpi/jwt_tool && ln -sf $PWD/jwt_tool/jwt_tool.py ~/.local/bin/jwt_tool
pip install --break-system-packages pycryptodome

# internal (requires a captured token): jwt_tool -X i <token>
jwt_tool -X i eyJhbGciOiJub25lIn0...
```

### curl-based wrappers (no install required — need `curl`)
- `http_methods` (HTTP_METHOD_TEST) — OPTIONS/TRACE/PUT/DELETE/PATCH verb test.
- `clickjack` (CLICKJACKING_TEST) — X-Frame-Options / CSP frame-ancestors check.
- `host_header` (HOST_HEADER_ATTACK) — non-canonical Host reflection / cache-poisoning probe.

---

## Phase 2 — Run-All Mode

Bypass the LLM planner and sweep every registered attack action:

```bash
python run_agent_loop.py <target> --run-all --auto-approve
# or
bin/cyberswarm attack <target> --run-all --auto-approve
```

---
## Install All Tools — One-Shot Script

```bash
#!/bin/bash
# Run from any directory. Installs all CyberSwarm tool dependencies.

set -e

echo "[*] System packages"
sudo apt update -q
sudo apt install -y nmap nikto whatweb openssl exploitdb dirb python3-pip

echo "[*] Python packages"
pip install dnspython requests ldap3 arjun linkfinder --break-system-packages

echo "[*] Go tools (requires Go 1.21+)"
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/amass/v4/...@master
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sensepost/gowitness@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

echo "[*] testssl.sh (TLS/SSL vulnerability scanner)"
sudo git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl
sudo ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl

echo "[*] Update nuclei templates"
nuclei -update-templates

echo "[*] Update searchsploit DB"
searchsploit -u

echo "[*] Install wpscan (optional — only needed for WordPress targets)"
gem install wpscan || echo "gem not found — install ruby first: sudo apt install ruby"

echo "[+] All tools installed"
```

---

## Run Commands

### Phase 1 — Recon



# Full recon (with human approval at each step)
python run_recon_loop.py sandbox.securegateway.com \
    --backend ollama --model qwen3:8b --base-url http://192.168.0.66:11434

# Auto-approve all steps (test/demo mode)
python run_recon_loop.py sandbox.securegateway.com \
    --backend ollama --model qwen3:8b --base-url http://192.168.0.66:11434 \
    --auto-approve

# Limit iterations
python run_recon_loop.py sandbox.securegateway.com \
    --backend ollama --model qwen3:8b --base-url http://192.168.0.66:11434 \
    --max-iter 10

# Generate Phase 1 report
python generate_report.py <target>
python generate_report.py <target> --out recon_report.md
python generate_report.py --all --out all_recon.md
```

### Phase 2 — Attack Mapping



# Attack loop (reads Phase 1 evidence automatically)
python run_attack_loop.py sandbox.securegateway.com \
    --backend ollama --model qwen3:8b --base-url http://192.168.0.66:11434

# Auto-approve (test mode)
python run_attack_loop.py sandbox.securegateway.com \
    --backend ollama --model qwen3:8b --base-url http://192.168.0.66:11434 \
    --auto-approve

# Limit iterations
python run_attack_loop.py sandbox.securegateway.com \
    --backend ollama --model qwen3:8b --base-url http://192.168.0.66:11434 \
    --max-iter 10

# Generate Phase 2 attack report
python generate_attack_report.py <target>
python generate_attack_report.py <target>
python generate_attack_report.py --all --out all_attacks.md
```



---

## Evidence File Locations

| File | Path | Description |
|---|---|---|
| Phase 1 recon evidence | `results/evidence/<target>.json` | Written by Phase 1, read by Phase 2 |
| Phase 2 attack evidence | `results/attack_evidence/<target>.json` | Written by Phase 2 |
| Phase 1 decision log | `results/decision_log.jsonl` | Every LLM decision + approval |
| Phase 2 decision log | `results/attack_decision_log.jsonl` | Every attack decision + approval |
| Screenshots | `results/screenshots/<target>/` | Gowitness captures |

---

