
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

## Installation Steps

1. **Create a New Repl**
   - Go to [Replit.com](https://replit.com)
   - Click "Create Repl"
   - Choose "Python" as the template
   - Name your repl (e.g., "url-security-scanner")
   - Click "Create Repl"

2. **Set Up Project Structure**
   ```
   /
   ├── instance/
   ├── static/
   │   ├── css/
   │   │   └── custom.css
   │   └── js/
   │       └── main.js
   ├── templates/
   │   ├── base.html
   │   ├── error.html
   │   ├── index.html
   │   ├── patterns.html
   │   └── results.html
   ├── analyzer.py
   ├── app.py
   ├── crawler.py
   ├── main.py
   └── models.py
   ```

3. **Install Dependencies**
   The following packages will be installed automatically through pyproject.toml:
   - beautifulsoup4 (>=4.13.4)
   - email-validator (>=2.2.0)
   - flask (>=3.1.1)
   - flask-sqlalchemy (>=3.1.1)
   - gunicorn (>=23.0.0)
   - psycopg2-binary (>=2.9.10)
   - requests (>=2.32.3)
   - trafilatura (>=2.0.0)
   - urllib3 (>=2.4.0)

4. **Create and Configure Files**
   - Copy all the source files (app.py, analyzer.py, crawler.py, etc.)
   - Copy the templates into the templates folder
   - Copy the static files (CSS/JS) into their respective folders
   - The SQLite database will be automatically created in the instance folder

5. **Run the Application**
   - Click the "Run" button in Replit
   - The application will start on port 5000
   - Access the web interface through your Repl's URL

6. **Verify Installation**
   - The main interface should show a URL input form
   - You should see the "What We Check For" section
   - No error messages should appear in the console
   - Try a test scan with a sample URL

7. **Troubleshooting**
   - If dependencies aren't installed, Replit will install them automatically
   - Check the console for any error messages
   - Ensure all files are in their correct directories
   - Make sure the database is created in the instance folder

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
