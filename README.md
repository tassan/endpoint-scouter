# EndpointScouter

---

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

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
git clone https://github.com/yourusername/endpoint-scouter.git
cd endpoint-scouter

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python endpoint_scouter.py endpoints.csv
```

### Advanced Options

```bash
python endpoint_scouter.py endpoints.json \
  --output report.json \
  --timeout 10 \
  --workers 20 \
  --rate-limit-test 15 \
  --test-vulnerabilities \
  --verbose
```

### Fun Mode

```bash
python endpoint_scouter.py endpoints.csv --dbz-mode
```

## Input File Format

EndpointScouter accepts CSV or JSON files with endpoint definitions.

### CSV Format

```csv
url,method,expected_status,headers
https://api.example.com/users,GET,200,{"Authorization":"Bearer token"}
https://api.example.com/admin,POST,401,{}
```

### JSON Format

```json
[
  {
    "url": "https://api.example.com/users",
    "method": "GET",
    "expected_status": 200,
    "headers": {
      "Authorization": "Bearer token"
    },
    "payload": null
  },
  {
    "url": "https://api.example.com/admin",
    "method": "POST",
    "expected_status": 401,
    "headers": {},
    "payload": { "username": "test" }
  }
]
```

## Command Line Options

| Option                   | Description                                            |
| ------------------------ | ------------------------------------------------------ |
| `endpoints_file`         | CSV or JSON file containing endpoints to check         |
| `-o, --output`           | Output file for the report (JSON)                      |
| `-t, --timeout`          | Timeout for requests in seconds (default: 5)           |
| `-w, --workers`          | Number of parallel workers (default: 10)               |
| `-r, --rate-limit-test`  | Number of requests to test rate limiting (default: 10) |
| `--dbz-mode`             | Enable Dragon Ball Z themed responses                  |
| `--test-vulnerabilities` | Test for common vulnerabilities                        |
| `-v, --verbose`          | Enable verbose logging                                 |

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
python endpoint_scouter.py production_endpoints.csv --output prod_security_report.json
```

### Testing for Vulnerabilities

```bash
python endpoint_scouter.py test_endpoints.json --test-vulnerabilities --verbose
```

## License

MIT
