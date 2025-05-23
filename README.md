
# URL Security Scanner

A web-based security scanning tool that crawls websites to detect potential security vulnerabilities in URLs. The application analyzes URLs for common security issues like SQL injection, XSS, command injection, and open redirect vulnerabilities.

## Features

- Website crawling with configurable depth
- Detection of multiple vulnerability types:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Open Redirect
  - Security Misconfiguration
  - CSRF Issues
  - IDOR
  - Path Traversal
  - Sensitive Pages
- Results export to CSV
- Customizable vulnerability patterns

## Setup

1. Fork this repl or create a new Flask repl
2. The application uses SQLite database which will be automatically created in the `instance` folder
3. No additional configuration is needed as all dependencies are handled by Replit

## Usage

1. Access the web interface through your Repl's URL
2. Enter a target URL in the form
3. Click "Start Scan" to begin the security analysis
4. View results categorized by vulnerability type
5. Export results to CSV if needed

## Crawling Mechanism

The crawler uses the following techniques:

- **Depth-First Crawling**: Explores URLs up to a configurable depth (default: 3)
- **Rate Limiting**: 1-second delay between requests to prevent overloading
- **URL Normalization**: Removes duplicates and standardizes URLs
- **Redirect Handling**: Follows HTTP redirects within the same domain

### What Gets Crawled:
- Internal links within the same domain
- Subdomains of the target domain
- Both HTTP and HTTPS URLs
- Static and dynamic pages

### What Doesn't Get Crawled:
- External domain links
- Non-HTTP protocols (ftp://, mailto:, etc.)
- URLs with fragments (#)
- JavaScript-generated URLs
- URLs requiring authentication
- Rate-limited or blocked requests (403, 429)

## Database

The application uses SQLite with Flask-SQLAlchemy for:
- Storing custom vulnerability patterns
- Pattern management through web interface
- Auto-creation of database on first run

Database location: `instance/patterns.db`

## Customizing Patterns

1. Navigate to the Patterns page
2. Each vulnerability type has an editable pattern
3. Patterns use regular expressions for matching
4. Changes are saved automatically and used in future scans

## Technical Details

- **Framework**: Flask
- **Database**: SQLite
- **HTML Parser**: BeautifulSoup4
- **HTTP Client**: Requests with retry mechanism
- **Max URLs**: 100 per scan (configurable)
- **Max Depth**: 3 levels (configurable)
- **Request Timeout**: 10 seconds

## Error Handling

- 403 Access Forbidden: Displays user-friendly message
- Rate limiting: Automatic retry with backoff
- Connection errors: Graceful failure with error reporting
- Invalid URLs: Input validation and error messages

## Required Modules

The application requires Python 3.11 or higher and the following dependencies:

- beautifulsoup4 (>=4.13.4) - HTML parsing and web scraping
- email-validator (>=2.2.0) - URL and email validation
- flask (>=3.1.1) - Web framework
- flask-sqlalchemy (>=3.1.1) - Database ORM
- gunicorn (>=23.0.0) - Production WSGI server
- psycopg2-binary (>=2.9.10) - PostgreSQL adapter
- requests (>=2.32.3) - HTTP client for crawling
- trafilatura (>=2.0.0) - Web content extraction
- urllib3 (>=2.4.0) - HTTP client library

All dependencies are automatically handled by Replit's environment.
