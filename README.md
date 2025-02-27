# EndpointScouter

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://github.com/tassan/endpoint-scouter/workflows/CI/badge.svg)](https://github.com/tassan/endpoint-scouter/actions)
[![Coverage Status](https://coveralls.io/repos/github/tassan/endpoint-scouter/badge.svg?branch=main)](https://coveralls.io/github/tassan/endpoint-scouter?branch=main)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=tassan_endpoint-scouter&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=tassan_endpoint-scouter)
[![Documentation Status](https://readthedocs.org/projects/endpoint-scouter/badge/?version=latest)](https://endpoint-scouter.readthedocs.io/en/latest/?badge=latest)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

🔍 **A tool for verifying security measures in API endpoints**

EndpointScouter allows you to quickly assess the security posture of your API endpoints by checking for best practices, security headers, rate limiting, and common vulnerabilities.

_Inspired by Dragon Ball Z Scouters - checks the "power level" of your endpoints' security!_

## Features

- **Header Analysis**: Checks for security headers and CORS configuration
- **Rate Limit Detection**: Tests if endpoints implement rate limiting
- **Vulnerability Scanning**: Detects common issues like open redirects
- **Parallel Processing**: Efficiently tests multiple endpoints simultaneously
- **Comprehensive Reporting**: Generates reports in JSON, CSV, and HTML formats
- **Security Scoring**: Provides meaningful security scores with recommendations

## Installation

```bash
# Clone the repository
git clone https://github.com/tassan/endpoint-scouter.git
cd endpoint-scouter

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python -m endpoint_scouter config/endpoints.yaml
```

### Advanced Options

```bash
python -m endpoint_scouter config/endpoints.yaml \
  --output custom_report \
  --format all \
  --verbose \
  --dbz-mode
```

### Fun Mode

```bash
python -m endpoint_scouter config/endpoints.yaml --dbz-mode
```

## Input File Format

EndpointScouter accepts YAML, JSON, or CSV files with endpoint definitions.

### YAML Format (Recommended)

```yaml
# Global settings
settings:
  timeout: 5
  max_workers: 10

# Tests to run
tests:
  security_headers: true
  cors_headers: true

# Endpoints to scan
endpoints:
  - url: https://api.example.com/users
    method: GET
    headers:
      Authorization: "Bearer token"
  - url: https://api.example.com/admin
    method: POST
    payload:
      username: "test"
```

### CSV Format

```csv
url,method,headers
https://api.example.com/users,GET,{"Authorization":"Bearer token"}
https://api.example.com/admin,POST,{}
```

### JSON Format

```json
[
  {
    "url": "https://api.example.com/users",
    "method": "GET",
    "headers": {
      "Authorization": "Bearer token"
    },
    "payload": null
  },
  {
    "url": "https://api.example.com/admin",
    "method": "POST",
    "headers": {},
    "payload": { "username": "test" }
  }
]
```

## Command Line Options

| Option          | Description                                           |
| --------------- | ----------------------------------------------------- |
| `config_file`   | YAML, JSON or CSV file with endpoints                 |
| `-o, --output`  | Output file prefix for reports                        |
| `--format`      | Report format(s): json, csv, html, all (default: all) |
| `-v, --verbose` | Enable verbose logging                                |
| `--dbz-mode`    | Enable Dragon Ball Z themed responses                 |

## Output Reports

EndpointScouter generates three types of reports:

### JSON Report

Contains detailed scan results including:

- Endpoint details
- Security headers
- CORS configuration
- Rate limiting information
- Detected vulnerabilities
- Overall security score

### CSV Report

Simplified tabular format for easy importing into spreadsheets.

### HTML Report

Visual report with:

- Color-coded security scores
- Domain-based statistics
- Interactive endpoint details
- Issue highlighting

## Security Score Interpretation

| Score Range | Interpretation                     |
| ----------- | ---------------------------------- |
| 8000+       | Excellent - Comprehensive security |
| 6000-7999   | Very Good - Strong security        |
| 5000-5999   | Good - Solid foundation            |
| 3000-4999   | Moderate - Basic security in place |
| 1000-2999   | Fair - Minimal protections         |
| 0-999       | Inadequate - Needs improvement     |

## Common Issues Detected

- Missing security headers
- Overly permissive CORS
- Lack of rate limiting
- Server information disclosure
- Directory listing enabled
- Open redirect vulnerabilities
- Non-HTTPS endpoints

## Examples

### Testing a Production API

```bash
python -m endpoint_scouter config/production.yaml --output prod_security_report
```

### Testing for Vulnerabilities

```bash
python -m endpoint_scouter config/test.yaml --verbose
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
