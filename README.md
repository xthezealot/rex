# Rex

Rex is an an all-in-one recon and vuln scanner.  
It's designed to be fast, simple, yet comprehensive.

It was first created with bug bounty needs in mind, replacing multi-tool workflows with a single command, and using only a readable YAML file per hunt.

## Features

- Full **parallelism**
- Scan **common ports**
- Discover **URL paths**
- Search for **subdomains** (use flag `-d`)
- Scan for common **vulnerabilities** (XSS, CRLF, …) (use flag `-s`)
- Save interesting **HTTP responses** for manual inspection
- Integrates a manually-filtered and high-quality **wordlist** (2200+)
- **Pretty print** (use subcommand `p`)

## Install

Download the latest [release](https://github.com/xthezealot/rex/releases) in `/usr/local/bin`.

Rex also depends on these external commands:

- [`subfinder`](https://github.com/projectdiscovery/subfinder)

# Usage

1. Run `rex` to create a base file in the current directory:

   ```bash
   rex
   ```

2. Add your scope to `hunt.yml` (a list of domain names, IP addresses or CIDR ranges):

   ```yml
   scope:
     - example.com
     - 111.111.111.111
     - 10.0.0.0/29
   ```

3. Run `rex` to parse the scope from `hunt.yml` and start hunting.  
   ⚠️ Rex sends a lot of parallel requests, so don't use your home IP address.

4. When scan is complete, get your results in `hunt.yml`.  
   For a more compact and readable output, there is the `rex p` command.

5. 50% of the job is done.  
   Now, move onto the 50% manual work to find P1 and P2 vulns.  
   You can start by analysing HTTP responses saved in the `http` directory.

# Complementary tools

Since Rex doesn't include every conceivable scanner, use these tools for a more thorough check:

```sh
# 40x bypass
# github.com/lobuhi/byp4xx
byp4xx <URL>

# CORS
./corsy.py -u <URL>

# Open redirect
./oralyzer.py -u <URL>

# Prototype pollution
ppfuzz -l <URLS_FILE>

# SQL injection
./sqlmap.py -u <URL>
ghauri -u <URL>

# SSL
# github.com/drwetter/testssl.sh
./testssl.sh <DOMAIN>

# Cache poisoning
# github.com/hackmanit/web-cache-vulnerability-scanner
wcvs -u <URL>
```
