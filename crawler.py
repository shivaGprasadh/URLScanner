import logging
import re
import requests
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import xml.etree.ElementTree as ET

# Set up logging
# Configure requests with retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.Session()
session.mount("https://", adapter)
session.mount("http://", adapter)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def is_valid_url(url):
    """
    Check if the URL is valid.

    Args:
        url (str): URL to check

    Returns:
        bool: True if the URL is valid, False otherwise
    """
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

# Sitemap functionality removed

def is_internal_link(base_url, url):
    """
    Check if a URL is an internal link relative to a base URL.

    Args:
        base_url (str): The base URL of the website being crawled
        url (str): The URL to check

    Returns:
        bool: True if the URL is an internal link, False otherwise
    """
    base_domain = urlparse(base_url).netloc
    url_domain = urlparse(url).netloc

    # Empty domain means it's a relative URL (internal)
    if not url_domain:
        return True

    # If domains match exactly, it's internal
    if url_domain == base_domain:
        return True

    # Check for subdomains - if the base domain is a subset of the URL domain
    # For example, blog.example.com is a subdomain of example.com
    if base_domain in url_domain or url_domain in base_domain:
        return True

    return False

def normalize_url(url):
    """
    Normalize a URL to avoid duplicate crawling.

    Args:
        url (str): The URL to normalize

    Returns:
        str: Normalized URL
    """
    parsed = urlparse(url)

    # Ensure the path ends with / for directory-like URLs
    path = parsed.path
    if not path:
        path = "/"

    # Convert to lowercase for case-insensitive comparison
    netloc = parsed.netloc.lower()
    scheme = parsed.scheme.lower()

    # Remove trailing slash except for root URL
    if path != "/" and path.endswith("/"):
        path = path[:-1]

    return f"{scheme}://{netloc}{path}"

def crawl_website(base_url, max_urls=100, max_depth=3, custom_sitemap_urls=None):
    """
    Crawl a website starting from a base URL and extract all internal links.
    Also check for sitemap.xml to find additional URLs.

    Args:
        base_url (str): The starting URL for crawling
        max_urls (int): Maximum number of URLs to crawl (to prevent infinite loops)
        max_depth (int): Maximum depth for recursive crawling
        custom_sitemap_url (str): Optional custom sitemap URL

    Returns:
        list: A list of discovered URLs
    """
    # Ensure base_url is properly formatted
    if not (base_url.startswith('http://') or base_url.startswith('https://')):
        base_url = 'https://' + base_url

    # URLs that have been discovered
    discovered_urls = set()

    # URLs that have been visited (use normalized URLs)
    visited_urls = set()

    # Depths for each URL
    url_depths = {base_url: 0}

    # URLs to visit next (URL, depth)
    to_visit = [base_url]

    # Base domain for checking internal links
    base_domain = urlparse(base_url).netloc

    # Track number of failures to avoid excessive errors
    failures = 0
    max_failures = 10  # Increased for better coverage

    logger.debug(f"Starting crawl from {base_url}")

    # Continue until there are no more URLs to visit or we've reached the maximum
    while to_visit and len(discovered_urls) < max_urls and failures < max_failures:
        # Get the next URL to visit
        current_url = to_visit.pop(0)

        # Get current depth
        current_depth = url_depths.get(current_url, 0)

        # Skip if exceeding maximum depth
        if current_depth > max_depth:
            continue

        # Normalize current URL for comparison
        normalized_current = normalize_url(current_url)

        # Skip if we've already visited this URL
        if normalized_current in [normalize_url(u) for u in visited_urls]:
            continue

        logger.debug(f"Crawling: {current_url} (depth: {current_depth})")

        # Mark as visited
        visited_urls.add(current_url)

        try:
            # Add headers and delay between requests
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            time.sleep(1)  # Add 1 second delay between requests
            response = requests.get(current_url, headers=headers, timeout=10)

            # Handle redirects - follow the chain
            if 300 <= response.status_code < 400 and 'Location' in response.headers:
                redirect_url = urljoin(current_url, response.headers['Location'])
                if is_internal_link(base_url, redirect_url) and is_valid_url(redirect_url):
                    logger.debug(f"Following redirect: {current_url} -> {redirect_url}")
                    to_visit.append(redirect_url)
                    url_depths[redirect_url] = current_depth  # Keep same depth for redirects
                continue

            # Skip if the response is not successful
            if response.status_code != 200:
                logger.warning(f"Failed to fetch {current_url}: HTTP {response.status_code}")
                continue

            # Add the URL to discovered URLs
            discovered_urls.add(current_url)

            # Only parse and extract links if content is HTML
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' in content_type or 'application/xhtml+xml' in content_type:
                try:
                    # Parse the HTML content
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Extract all links
                    for link in soup.find_all('a', href=True):
                        href = link['href']

                        # Skip empty links, fragments, and javascript links
                        if not href or href.startswith('#') or href.startswith('javascript:'):
                            continue

                        # Create an absolute URL if the link is relative
                        full_url = urljoin(current_url, href)

                        # Skip non-http protocols
                        if not (full_url.startswith('http://') or full_url.startswith('https://')):
                            continue

                        # Get normalized version for comparison
                        normalized_url = normalize_url(full_url)

                        # Check if this is an internal link
                        if is_internal_link(base_url, full_url):
                            # Add to discovered URLs (with original query parameters)
                            discovered_urls.add(full_url)

                            # Check if we should add it to the visit queue
                            normalized_visited = [normalize_url(u) for u in visited_urls]
                            normalized_to_visit = [normalize_url(u) for u in to_visit]

                            # Only visit if we haven't seen it yet and within depth limit
                            if (normalized_url not in normalized_visited and 
                                normalized_url not in normalized_to_visit and
                                is_valid_url(full_url) and
                                current_depth + 1 <= max_depth):
                                to_visit.append(full_url)
                                # Store the depth for this URL (one level deeper than current)
                                url_depths[full_url] = current_depth + 1
                except Exception as e:
                    logger.error(f"Error parsing HTML at {current_url}: {str(e)}")

        except Exception as e:
            logger.error(f"Error crawling {current_url}: {str(e)}")
            failures += 1

    logger.debug(f"Crawl complete. Discovered {len(discovered_urls)} URLs")

    return list(discovered_urls)