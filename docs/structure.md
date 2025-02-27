# EndpointScouter Project Structure

## Directory Structure

```
endpoint-scouter/
├── .github/                     # GitHub specific files
│   ├── workflows/               # GitHub Actions workflows
│   └── ISSUE_TEMPLATE/          # Issue templates
├── docs/                        # Documentation
│   ├── user-guide.md            # User documentation
│   └── developer-guide.md       # Developer documentation
├── tests/                       # Test suite
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   └── fixtures/                # Test data
├── endpoint_scouter/            # Main package
│   ├── __init__.py              # Package initialization
│   ├── cli.py                   # Command line interface
│   ├── config.py                # Configuration handling
│   ├── core/                    # Core functionality
│   │   ├── __init__.py
│   │   ├── scanner.py           # Main scanner logic
│   │   ├── endpoint.py          # Endpoint models
│   │   └── result.py            # Result models
│   ├── analyzers/               # Security analyzers
│   │   ├── __init__.py
│   │   ├── headers.py           # Security headers analysis
│   │   ├── cors.py              # CORS configuration analysis
│   │   ├── rate_limit.py        # Rate limiting detection
│   │   └── vulnerabilities.py   # Vulnerability scanners
│   ├── reporters/               # Report generators
│   │   ├── __init__.py
│   │   ├── json_reporter.py     # JSON report generation
│   │   ├── csv_reporter.py      # CSV report generation
│   │   └── html_reporter.py     # HTML report generation
│   └── utils/                   # Utility functions
│       ├── __init__.py
│       ├── http.py              # HTTP utilities
│       ├── scoring.py           # Security scoring logic
│       └── validators.py        # Input validation
├── examples/                    # Example configurations and usage
├── .gitignore                   # Git ignore file
├── LICENSE                      # License file
├── README.md                    # Project README
├── requirements.txt             # Project dependencies
├── setup.py                     # Package setup script
└── pyproject.toml               # Project metadata and config
```

## Module Organization

### Core Modules

1. **Scanner Module (`core/scanner.py`)**

   - Central orchestration of the scanning process
   - Thread management and coordination
   - Overall scan lifecycle

2. **Endpoint Module (`core/endpoint.py`)**

   - Endpoint representation and validation
   - Parsing endpoint configurations
   - Standardizing endpoint data

3. **Result Module (`core/result.py`)**
   - Scan result data structures
   - Result aggregation and summarization
   - Security score calculations

### Analyzer Modules

1. **Headers Analyzer (`analyzers/headers.py`)**

   - Security header detection and validation
   - Header policy enforcement checking

2. **CORS Analyzer (`analyzers/cors.py`)**

   - CORS configuration analysis
   - Cross-origin policy evaluation

3. **Rate Limit Analyzer (`analyzers/rate_limit.py`)**

   - Rate limiting detection strategies
   - Rate limit header parsing and validation

4. **Vulnerability Analyzer (`analyzers/vulnerabilities.py`)**
   - Open redirect testing
   - Server information disclosure detection
   - Directory listing checks
   - Other common vulnerability tests

### Reporter Modules

1. **JSON Reporter (`reporters/json_reporter.py`)**

   - Detailed JSON report generation

2. **CSV Reporter (`reporters/csv_reporter.py`)**

   - Tabular CSV report generation

3. **HTML Reporter (`reporters/html_reporter.py`)**
   - Visual HTML report generation with styling

### Utility Modules

1. **HTTP Utilities (`utils/http.py`)**

   - Request handling with retries
   - Session management
   - Response processing

2. **Scoring Logic (`utils/scoring.py`)**

   - Security score calculations
   - Scoring rules and thresholds

3. **Validators (`utils/validators.py`)**
   - Input validation for configurations
   - Schema validation for endpoints

## Class Design

### Core Classes

```python
class EndpointScouter:
    """Main orchestrator class that manages the scanning process."""

    def __init__(self, config):
        self.config = config
        self.results = []
        self.analyzers = self._setup_analyzers()
        self.reporters = self._setup_reporters()

    def load_endpoints(self, file_path):
        """Load and standardize endpoints from file."""
        pass

    def scan_all(self, endpoints):
        """Scan all endpoints using thread pool."""
        pass

    def generate_reports(self, output_prefix):
        """Generate all configured reports."""
        pass
```

```python
class Endpoint:
    """Represents an API endpoint to be scanned."""

    def __init__(self, url, method="GET", expected_status=None, headers=None, payload=None):
        self.url = url
        self.method = method.upper()
        self.expected_status = expected_status
        self.headers = headers or {}
        self.payload = payload
```

```python
class ScanResult:
    """Stores the results of an endpoint scan."""

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.timestamp = datetime.now().isoformat()
        self.is_accessible = False
        self.status_code = None
        self.security_headers = {}
        self.cors_headers = {}
        self.rate_limit_detected = False
        self.vulnerabilities = {}
        self.issues = []
        self.errors = []
```

### Analyzer Classes

```python
class BaseAnalyzer:
    """Base class for all analyzers."""

    def __init__(self, config):
        self.config = config

    def analyze(self, response, result):
        """Analyze response and update result."""
        raise NotImplementedError("Subclasses must implement analyze()")
```

```python
class HeaderAnalyzer(BaseAnalyzer):
    """Analyzes security headers in responses."""

    def analyze(self, response, result):
        """Check for security headers and update result."""
        pass
```

### Reporter Classes

```python
class BaseReporter:
    """Base class for all reporters."""

    def __init__(self, config):
        self.config = config

    def generate(self, results, output_file):
        """Generate report from results."""
        raise NotImplementedError("Subclasses must implement generate()")
```

## Configuration Management

### Configuration Schema

Store configurations in YAML or JSON format:

```yaml
# config.yaml
scanner:
  timeout: 5
  max_workers: 10
  rate_limit_test_count: 10
  test_vulnerabilities: true

security:
  required_headers:
    - Strict-Transport-Security
    - Content-Security-Policy
    - X-Content-Type-Options

  header_policies:
    Strict-Transport-Security:
      min_age: 31536000

reporting:
  formats:
    - json
    - csv
    - html
  include_details: true
```

## Testing Strategy

1. **Unit Tests**

   - Test individual analyzers with mock responses
   - Test reporters with sample result data
   - Test utility functions in isolation

2. **Integration Tests**

   - Test the full scanning process with mock servers
   - Verify report generation end-to-end
   - Test with different configuration options

3. **Mock Server**
   - Create a simple mock server with endpoints that have specific security characteristics

## Development Workflow

1. **Feature Branches**

   - Create feature branches for each improvement
   - Use `feature/name-of-feature` naming convention

2. **Pull Request Process**

   - Require tests for new features
   - Enforce code style through linting
   - Require documentation updates

3. **Continuous Integration**

   - Run tests on pull requests
   - Run security checks on dependencies
   - Generate test coverage reports

4. **Release Process**
   - Semantic versioning (MAJOR.MINOR.PATCH)
   - Generate release notes from commits
   - Create GitHub releases with assets

## Extension Points

Design the system with these extension points:

1. **Custom Analyzers**

   - Allow registering custom analyzer plugins
   - Define standard analyzer interface

2. **Custom Reporters**

   - Support custom report formats
   - Define reporter registration mechanism

3. **Custom Vulnerability Tests**
   - Support adding new vulnerability tests
   - Define test registration interface

## Implementation Plan

1. **Phase 1: Core Refactoring**

   - Restructure existing code into the module organization
   - Split the monolithic class into specialized modules
   - Implement the base interfaces

2. **Phase 2: Add Extension Points**

   - Create plugin architecture
   - Implement configuration system
   - Add extension documentation

3. **Phase 3: Implement New Features**
   - Follow milestone plan to implement new features
   - Integration with development workflow
