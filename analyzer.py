import logging
from urllib.parse import urlparse, parse_qs

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define patterns for different vulnerability types
SQL_INJECTION_PARAMS = ['id', 'user', 'userid', 'username', 'account', 'acc', 'product', 
                        'prod', 'item', 'order', 'oid', 'category', 'cat', 'page', 
                        'num', 'limit', 'offset', 'search', 'filter']

XSS_PARAMS = ['search', 'q', 'query', 'keyword', 'term', 'text', 'msg', 'message', 
              'input', 'comment', 'desc', 'description', 'title', 'name']

COMMAND_INJECTION_PARAMS = ['cmd', 'exec', 'command', 'run', 'script', 'action', 
                           'task', 'process', 'shell', 'system']

OPEN_REDIRECT_PARAMS = ['url', 'redirect', 'next', 'return', 'dest', 'destination', 
                        'redir', 'goto', 'callback', 'continue', 'page']

# Additional vulnerability types
SENSITIVE_DATA_PARAMS = ['token', 'auth', 'password', 'pass', 'pwd', 'secret', 'key', 
                         'apikey', 'access_token', 'session', 'ssn', 'creditcard', 
                         'cc', 'card', 'cvv', 'pin', 'private']

BROKEN_AUTH_PARAMS = ['login', 'logout', 'signin', 'signout', 'user', 'username', 
                      'auth', 'sessionid', 'session', 'token', 'access_token', 
                      'refresh_token']

SECURITY_MISCONFIG_PATHS = ['/admin', '/administrator', '/debug', '/console', '/setup', 
                           '/config', '/config.php', '/phpinfo.php', '/env', '/.env', 
                           '/status']

CSRF_PARAMS = ['csrf_token', 'csrfmiddlewaretoken', '_token']

IDOR_PARAMS = ['id', 'userid', 'user_id', 'orderid', 'file', 'filename', 'document', 
               'doc', 'record', 'recordid', 'resource', 'itemid']

PATH_TRAVERSAL_PARAMS = ['file', 'filename', 'path', 'dir', 'folder', 'document']
PATH_TRAVERSAL_PATTERNS = ['../', '%2e%2e%2f']

SENSITIVE_PAGES = [
    'privacy', 'privacy-policy', 'privacy_policy', 'privacy-notice', 'privacy_notice',
    'terms', 'terms-and-conditions', 'terms_of_service', 'terms-of-use', 'terms_of_use', 'tos',
    'security', 'security-policy', 'security_policy',
    'disclosure', 'information-disclosure',
    'about', 'contact', 'support', 'help', 'faq',
    'legal', 'compliance', 'gdpr', 'trust',
    'cookie', 'cookie-policy', 'cookie_policy', 'cookies', 'cookie_notice', 'cookie-notice',
    'accessibility'
]

def analyze_urls(urls):
    """
    Analyze a list of URLs to detect potential security vulnerabilities.
    
    Args:
        urls (list): List of URLs to analyze
        
    Returns:
        dict: Dictionary with categorized URLs by vulnerability type
    """
    # Initialize results dictionary
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
            
            # Get query parameters
            query_params = parse_qs(parsed_url.query)
            
            # Skip URLs without query parameters
            if not query_params:
                continue
                
            # Check for SQL injection vulnerabilities
            for query_param in query_params.keys():
                if any(sql_param in query_param.lower() for sql_param in SQL_INJECTION_PARAMS):
                    results['sql_injection'].append({
                        'url': url,
                        'parameter': query_param,
                        'value': query_params[query_param][0]
                    })
                    
            # Check for XSS vulnerabilities
            for param in XSS_PARAMS:
                if param in query_params:
                    results['xss'].append({
                        'url': url,
                        'parameter': param,
                        'value': query_params[param][0]
                    })
                    
            # Check for command injection vulnerabilities
            for param in COMMAND_INJECTION_PARAMS:
                if param in query_params:
                    results['command_injection'].append({
                        'url': url,
                        'parameter': param,
                        'value': query_params[param][0]
                    })
                    
            # Check for open redirect vulnerabilities
            for param in OPEN_REDIRECT_PARAMS:
                if param in query_params:
                    param_value = query_params[param][0]
                    # Check if the parameter value is an external URL
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
                    
            # Check for sensitive data exposure
            for param in SENSITIVE_DATA_PARAMS:
                if param in query_params:
                    results['sensitive_data_exposure'].append({
                        'url': url,
                        'parameter': param,
                        'value': query_params[param][0]
                    })
                    
            # Check for broken authentication
            for param in BROKEN_AUTH_PARAMS:
                if param in query_params:
                    results['broken_authentication'].append({
                        'url': url,
                        'parameter': param,
                        'value': query_params[param][0]
                    })
                    
            # Check for CSRF
            for param in CSRF_PARAMS:
                if param in query_params:
                    results['csrf'].append({
                        'url': url,
                        'parameter': param,
                        'value': query_params[param][0]
                    })
                    
            # Check for IDOR
            for param in IDOR_PARAMS:
                if param in query_params:
                    results['idor'].append({
                        'url': url,
                        'parameter': param,
                        'value': query_params[param][0]
                    })
                    
            # Check for path traversal in parameters
            for param in PATH_TRAVERSAL_PARAMS:
                if param in query_params:
                    param_value = query_params[param][0]
                    # Check if value contains path traversal patterns
                    has_traversal_pattern = any(pattern in param_value for pattern in PATH_TRAVERSAL_PATTERNS)
                    
                    results['path_traversal'].append({
                        'url': url,
                        'parameter': param,
                        'value': param_value,
                        'has_traversal_pattern': has_traversal_pattern
                    })
                    
            # Check for security misconfigurations (path-based)
            path = parsed_url.path.lower()
            for misconfig_path in SECURITY_MISCONFIG_PATHS:
                if misconfig_path in path:
                    results['security_misconfiguration'].append({
                        'url': url,
                        'path': path,
                        'matched_pattern': misconfig_path
                    })
                    break

            # Check for sensitive/compliance pages
            path = parsed_url.path.lower().strip('/')
            path_parts = path.split('/')
            for sensitive_page in SENSITIVE_PAGES:
                if any(sensitive_page in part for part in path_parts):
                    results['sensitive_pages'].append({
                        'url': url,
                        'path': path,
                        'matched_pattern': sensitive_page
                    })
                    break
                    
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {str(e)}")
            
    # Log summary of findings
    logger.debug(f"Analysis complete. Found {sum(len(v) for v in results.values())} potential vulnerabilities")
    
    return results
