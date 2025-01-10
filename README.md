# WP Vuln Scanner by s3rgeym

WP Vuln Scanner is a command-line utility designed to scan WordPress sites for vulnerabilities in plugins. It checks plugin versions against a database of known vulnerabilities (CVEs) and outputs the results in a structured format. The tool supports concurrency, customizable scanning parameters, and loading vulnerabilities from YAML or TOML files.

---

## Features

- 🚀 **Fast Scanning**: Concurrent scanning of multiple plugins for efficient results.
- ✅ **Structured Output**: Results are displayed in a clear, easy-to-read format.
- 📄 **YAML/TOML Support**: Load vulnerabilities from YAML or TOML configuration files.
- 🛠️ **Customizable**: Configure timeouts, delays, DNS settings, and more.
- 📊 **Logging**: Detailed logging with support for levels (info, warn, error, debug).

---

## Installation

1. Ensure you have Go installed (version 1.23 or higher).
2. Clone the repository:
   ```bash
   git clone https://github.com/s3rgeym/wp-vuln-scanner.git
   cd wp-vuln-scanner
   ```
3. Build the utility:
   ```bash
   go build -o wp-vuln-scanner .
   ```

---

## Usage

### Basic Usage

```bash
nohup ./wp-vuln-scanner -i urls.txt -log debug -o wp-vulns.json > output.log 2>&1 &
```

### Command-Line Options

| Flag              | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `-i`              | Input file containing URLs to scan (default: stdin).                        |
| `-o`              | Output file to save results (default: stdout).                              |
| `-c`              | Maximum number of concurrent requests (default: 20).                        |
| `-t`              | HTTP request timeout (default: 15s).                                        |
| `-rt`             | Per-request timeout (default: 5s).                                          |
| `-d`              | Delay between requests (default: 50ms).                                    |
| `-dns-server`     | Custom DNS server for domain resolution (default: system DNS).              |
| `-dns-proto`      | DNS protocol to use (default: udp).                                         |
| `-log`            | Logging level (debug, info, warn, error) (default: info).                   |
| `-f`              | Path to a YAML/TOML file containing vulnerability definitions.              |

---

## Example Input File (`urls.txt`)

```
https://example.com
https://another-site.com
```

---

## Example Vulnerability File (`wp-vulns.yaml`)

```yaml
- cve_id: "CVE-2024-28000"
  product_name: "litespeed-cache"
  product_type: "plugin"
  max_version: "6.3.0.1"

- cve_id: "CVE-2024-10924"
  product_name: "really-simple-ssl"
  product_type: "plugin"
  min_version: "9.0.0"
  max_version: "9.1.1.1"
```

---

## Example Output

```json
{"site_url":"https://www.example.com/","title":"Example Site","vuln_products":[{"cve_id":"CVE-2024-28000","product_name":"litespeed-cache","product_type":"plugin","version":"2.9.4.1"}],"server":"Apache","start_time":"2025-01-10T07:32:09.61941203+03:00","end_time":"2025-01-10T07:32:11.516537033+03:00"}
```

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
