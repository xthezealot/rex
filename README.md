# Rex

Rex is an an all-in-one recon and vuln scanner.  
It's designed to be fast, simple, yet comprehensive.

It was first created with bug bounty needs in mind, replacing multi-tool workflows with a single command, and using only a readable YAML file per hunt.

## Features

- Full **parallelism**
- Scan **common ports**
- Discover **URL paths** form an integrated wordlist of manually filtered and high-quality keywords (2200+)
- Search for **subdomains** (use flag `-s`)
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
