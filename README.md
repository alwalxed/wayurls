# WayURLS

A CLI tool to fetch URLs from various sources including Wayback Machine, Common Crawl, and VirusTotal.

## Installation

```bash
go install github.com/alwalxed/wayurls@latest
```

## Usage

```plaintext
wayurls [OPTIONS] [DOMAIN...]

Options:
  -d               Show fetch date in first column
  -t <domain|file> Target domain or file with list of domains
  -n               Exclude subdomains
  -o <file>        Output file (default: stdout)
  -v               List crawled URL versions
  -vt <key>        VirusTotal API key
```

## Examples

```bash
# Fetch URLs for a single domain
wayurls example.com

# Fetch URLs from a list of domains
wayurls -t domains.txt -o results.txt

# Fetch URLs with dates, excluding subdomains
wayurls -d -n -t example.com

# List crawled versions of URLs
wayurls -v example.com
```

## Contributing

Contributions are welcome via pull requests.

## License

[MIT](https://github.com/alwalxed/wayurls/blob/main/LICENSE)
