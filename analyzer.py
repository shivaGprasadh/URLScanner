import logging
import re
from urllib.parse import urlparse, parse_qs

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define regex patterns for different vulnerability types
SQL_INJECTION_PATTERN = r'(?i)(?:[\?&](?:id|page_id|user|userid|username|account|acc|product|prod|item|order|oid|category|cat|page|num|limit|offset|search|filter)=[\w-]*|\/(id|user|product|category)\/\d+)'

XSS_PATTERN = r'(?i)(search|q|query|keyword|term|text|msg|message|input|comment|desc|description|title|name)=.*'

COMMAND_INJECTION_PATTERN = r'(?i)(cmd|exec|command|run|script|action|task|process|shell|system)=.*'

OPEN_REDIRECT_PATTERN = r'(?i)(url|redirect|next|return|dest|destination|redir|goto|callback|continue|page)=.*'

SENSITIVE_DATA_PATTERN = r'(?i)(token|auth|password|pass|pwd|secret|key|apikey|access_token|session|ssn|creditcard|cc|card|cvv|pin|private)=.*'

BROKEN_AUTH_PATTERN = r'(?i)(login|logout|signin|signout|user|username|auth|sessionid|session|token|access_token|refresh_token)=.*'

SECURITY_MISCONFIG_PATTERN = r'(?i)/(admin|administrator|debug|console|setup|config|config\.php|phpinfo\.php|env|\.env|status)/?$'

CSRF_PATTERN = r'(?i)(csrf_token|csrfmiddlewaretoken|_token)=.*'

IDOR_PATTERN = r'(?i)(id|userid|user_id|orderid|file|filename|document|doc|record|recordid|resource|itemid)=.*'

PATH_TRAVERSAL_PATTERN = r'(?i)(file|filename|path|dir|folder|document)=.*(\.\./|%2e%2e%2f)'

SENSITIVE_PAGES_PATTERN = r'(?i)/(privacy|terms|security|disclosure|about|contact|support|help|faq|legal|compliance|gdpr|trust|cookie|accessibility)/?'

def analyze_urls(urls):
    """
    Analyze a list of URLs to detect potential security vulnerabilities using regex patterns.

    Args:
        urls (list): List of URLs to analyze

    Returns:
        dict: Dictionary with categorized URLs by vulnerability type
    """
    results = {
        'sql_injection': [],
        'xss': [],
        'command_injection': [],
        'open_redirect': [],
        'sensitive_data_exposure': [],
        'broken_authentication': [],
        'security_misconfiguration': [],
        'csrf': [],
        'idor': [],
        'path_traversal': [],
        'sensitive_pages': []
    }

    logger.debug(f"Analyzing {len(urls)} URLs")

    for url in urls:
        try:
            # Parse the URL
            parsed_url = urlparse(url)
            query = parsed_url.query
            path = parsed_url.path

            # Check each vulnerability pattern
            # Check for SQL injection in both query parameters and URL path
            try:
                sql_matches = re.finditer(SQL_INJECTION_PATTERN, url)
                for sql_match in sql_matches:
                    matched_text = sql_match.group(0)
                    if '=' in matched_text:
                        # Extract parameter from query string
                        param = re.search(r'[\?&]([^=]+)=', matched_text).group(1)
                        query_params = parse_qs(query)
                        if param in query_params:
                            results['sql_injection'].append({
                                'url': url,
                                'parameter': param,
                                'value': query_params[param][0],
                                'type': 'query_param'
                            })
                    else:
                        # Handle path-based parameters
                        param = re.search(r'/([^/]+)/\d+', matched_text).group(1)
                        results['sql_injection'].append({
                            'url': url,
                            'parameter': param,
                            'value': matched_text,
                            'type': 'path_param'
                        })
            except Exception as e:
                logger.warning(f"Error processing SQL injection pattern for {url}: {str(e)}")

            if re.search(XSS_PATTERN, query):
                param = re.search(XSS_PATTERN, query).group(1)
                results['xss'].append({
                    'url': url,
                    'parameter': param,
                    'value': parse_qs(query)[param][0]
                })

            if re.search(COMMAND_INJECTION_PATTERN, query):
                param = re.search(COMMAND_INJECTION_PATTERN, query).group(1)
                results['command_injection'].append({
                    'url': url,
                    'parameter': param,
                    'value': parse_qs(query)[param][0]
                })

            if re.search(OPEN_REDIRECT_PATTERN, query):
                param = re.search(OPEN_REDIRECT_PATTERN, query).group(1)
                param_value = parse_qs(query)[param][0]
                is_external = False
                if param_value.startswith(('http://', 'https://', '//')):
                    param_url_domain = urlparse(param_value).netloc
                    current_url_domain = parsed_url.netloc
                    is_external = param_url_domain and param_url_domain != current_url_domain

                results['open_redirect'].append({
                    'url': url,
                    'parameter': param,
                    'value': param_value,
                    'is_external': is_external
                })

            if re.search(SENSITIVE_DATA_PATTERN, query):
                param = re.search(SENSITIVE_DATA_PATTERN, query).group(1)
                results['sensitive_data_exposure'].append({
                    'url': url,
                    'parameter': param,
                    'value': parse_qs(query)[param][0]
                })

            if re.search(BROKEN_AUTH_PATTERN, query):
                param = re.search(BROKEN_AUTH_PATTERN, query).group(1)
                results['broken_authentication'].append({
                    'url': url,
                    'parameter': param,
                    'value': parse_qs(query)[param][0]
                })

            if re.search(SECURITY_MISCONFIG_PATTERN, path):
                results['security_misconfiguration'].append({
                    'url': url,
                    'path': path,
                    'matched_pattern': re.search(SECURITY_MISCONFIG_PATTERN, path).group(1)
                })

            if re.search(CSRF_PATTERN, query):
                param = re.search(CSRF_PATTERN, query).group(1)
                results['csrf'].append({
                    'url': url,
                    'parameter': param,
                    'value': parse_qs(query)[param][0]
                })

            if re.search(IDOR_PATTERN, query):
                param = re.search(IDOR_PATTERN, query).group(1)
                results['idor'].append({
                    'url': url,
                    'parameter': param,
                    'value': parse_qs(query)[param][0]
                })

            if re.search(PATH_TRAVERSAL_PATTERN, query):
                param = re.search(PATH_TRAVERSAL_PATTERN, query).group(1)
                results['path_traversal'].append({
                    'url': url,
                    'parameter': param,
                    'value': parse_qs(query)[param][0],
                    'has_traversal_pattern': True
                })

            if re.search(SENSITIVE_PAGES_PATTERN, path):
                results['sensitive_pages'].append({
                    'url': url,
                    'path': path,
                    'matched_pattern': re.search(SENSITIVE_PAGES_PATTERN, path).group(1)
                })

        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {str(e)}")

    logger.debug(f"Analysis complete. Found {sum(len(v) for v in results.values())} potential vulnerabilities")

    return results