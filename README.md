# Compliance CLI

A command-line tool for automated security compliance testing of open-source web applications, focusing on WordPress. The tool checks compliance against **OWASP Top 10 2021** and **CIS Benchmarks (Level 1)** for Apache and Nginx web servers, helping developers and system administrators identify and fix security misconfigurations and vulnerabilities.

## Overview

This tool automates security compliance testing for open-source web applications, with a focus on WordPress. It performs:
- **Reconnaissance**: Identifies WordPress core version, plugins, and themes.
- **Dynamic Scanning**: Checks HTTP headers, sensitive files, and correlates vulnerabilities using the WPScan API.
- **Configuration Analysis**: Analyzes Apache (`httpd.conf`) or Nginx (`nginx.conf`) configuration files against CIS Benchmarks.
- **Reporting**: Generates detailed reports in JSON or HTML format, including findings, severity, and remediation steps.

The tool is designed as a modular, extensible Proof of Concept (PoC), following the "Compliance as Code" philosophy, with rules defined in YAML files for easy customization.

## Installation

### Prerequisites
- Python 3.9 or higher
- (Optional) Poetry for dependency management
- Git for cloning the repository

### Option 1: Install with Poetry (Recommended)
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/compliance-cli.git
   cd compliance-cli
   ```
2. Install Poetry (if not already installed):
   ```bash
   pip install poetry
   ```
3. Install dependencies:
   ```bash
   poetry install
   ```
4. Activate the virtual environment:
   ```bash
   poetry shell
   ```

### Option 2: Install with pip
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/compliance-cli.git
   cd compliance-cli
   ```
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Run the tool using the command-line interface (CLI):

```bash
python -m compliance_cli --url <target-url> [OPTIONS]
```

### Options
- `--url TEXT`: URL of the target WordPress application (required, e.g., `https://example.com`).
- `--config-path PATH`: Path to web server config file (e.g., `nginx.conf` or `httpd.conf`) (optional).
- `--rules-dir PATH`: Directory containing compliance rules in YAML format (default: `rules`).
- `--out PATH`: Output file for scan results (JSON or HTML, default: `report.json`).
- `--verbose`: Enable verbose output for debugging.

### Example
```bash
python -m compliance_cli --url https://example.com --config-path /etc/nginx/nginx.conf --out report.html --verbose
```

This will scan the target WordPress site, analyze the provided Nginx config file, and generate an HTML report.

## Legal Notice
This tool is designed for **security compliance testing** on systems you own or have explicit permission to test. Unauthorized scanning of websites or servers may violate laws or terms of service. Use responsibly and ensure compliance with all applicable regulations.

## Project Structure
```
compliance-cli/
├── src/compliance_cli/   # Source code for the CLI tool
├── rules/                # YAML rules for compliance checks
├── tests/                # Unit and integration tests
├── examples/             # Docker-based demo environment
├── docs/                 # Documentation (architecture, rules schema)
├── pyproject.toml        # Poetry configuration
├── requirements.txt       # Dependencies for pip-based installation
└── README.md             # This file
```

## Development
- **Linting and Formatting**: Use `poetry run pre-commit run --all-files` to run Black, isort, flake8, and yamllint.
- **Testing**: Run tests with `poetry run pytest` to ensure >80% code coverage.
- **Adding Dependencies**: Use `poetry add <package>` for runtime dependencies or `poetry add --dev <package>` for dev dependencies.
- **Gitignore**: The `.gitignore` file excludes temporary files, virtual environments, and output reports to keep the repository clean.

## Roadmap
- Week 3-4: Implement logging and HTTP utilities.
- Week 5-8: Develop scanning modules (recon, HTTP headers, config analysis).
- Week 9-10: Add reporting (JSON and HTML) and end-to-end tests.
- Week 11-12: Finalize documentation and demo scenarios.

## Contributing
Contributions are welcome! Please fork the repository, create a feature branch, and submit a pull request. Ensure all tests pass and code is formatted with Black.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.