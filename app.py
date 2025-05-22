import os
import logging
import csv
import io
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, jsonify

from crawler import crawl_website
from analyzer import analyze_urls

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key-for-development")

@app.route('/', methods=['GET', 'POST'])
def index():
    """Handle the home page with the URL input form."""
    if request.method == 'POST':
        base_url = request.form.get('base_url', '').strip()
        
        # Basic URL validation
        if not base_url:
            flash('Please enter a URL', 'danger')
            return render_template('index.html')
            
        # Check if URL starts with http:// or https://
        if not (base_url.startswith('http://') or base_url.startswith('https://')):
            base_url = 'https://' + base_url
            
        # Store the base URL in session for potential use later
        session['base_url'] = base_url
        
        try:
            # Get optional sitemap URLs
            custom_sitemap_urls = request.form.getlist('sitemap_urls[]')
            custom_sitemap_urls = [url.strip() for url in custom_sitemap_urls if url.strip()]
            
            # Crawl the website to get all URLs
            logger.debug(f"Starting crawl of {base_url}")
            discovered_urls = crawl_website(base_url, custom_sitemap_urls=custom_sitemap_urls)
            
            if not discovered_urls:
                flash('No URLs were discovered. Please check the URL and try again.', 'warning')
                return render_template('index.html')
                
            # Analyze the discovered URLs for potential vulnerabilities
            logger.debug(f"Analyzing {len(discovered_urls)} discovered URLs")
            analysis_results = analyze_urls(discovered_urls)
            
            # Store the results in session for display
            session['analysis_results'] = analysis_results
            session['total_urls'] = len(discovered_urls)
            session['discovered_urls'] = discovered_urls
            
            # Redirect to results page
            return redirect(url_for('results'))
            
        except Exception as e:
            logger.error(f"Error during crawling or analysis: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'danger')
            return render_template('error.html', error=str(e))
    
    return render_template('index.html')

@app.route('/results')
def results():
    """Display the analysis results."""
    # Get the analysis results from session
    analysis_results = session.get('analysis_results')
    base_url = session.get('base_url')
    total_urls = session.get('total_urls', 0)
    discovered_urls = session.get('discovered_urls', [])
    
    if not analysis_results:
        flash('No analysis results available. Please scan a URL first.', 'warning')
        return redirect(url_for('index'))
        
    # Count totals for each vulnerability type
    vulnerability_counts = {
        'sql_injection': len(analysis_results.get('sql_injection', [])),
        'xss': len(analysis_results.get('xss', [])),
        'command_injection': len(analysis_results.get('command_injection', [])),
        'open_redirect': len(analysis_results.get('open_redirect', [])),
        'sensitive_data_exposure': len(analysis_results.get('sensitive_data_exposure', [])),
        'broken_authentication': len(analysis_results.get('broken_authentication', [])),
        'security_misconfiguration': len(analysis_results.get('security_misconfiguration', [])),
        'csrf': len(analysis_results.get('csrf', [])),
        'idor': len(analysis_results.get('idor', [])),
        'path_traversal': len(analysis_results.get('path_traversal', [])),
        'sensitive_pages': len(analysis_results.get('sensitive_pages', []))
    }
    
    return render_template(
        'results.html',
        analysis_results=analysis_results,
        base_url=base_url,
        total_urls=total_urls,
        vulnerability_counts=vulnerability_counts,
        discovered_urls=discovered_urls
    )

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('error.html', error='Page not found'), 404

@app.route('/export_csv')
def export_csv():
    """Export the analysis results as CSV."""
    # Get the analysis results and urls from session
    analysis_results = session.get('analysis_results')
    discovered_urls = session.get('discovered_urls', [])
    base_url = session.get('base_url', '')
    
    if not analysis_results:
        flash('No analysis results available to export.', 'warning')
        return redirect(url_for('index'))
    
    # Create a CSV output in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(['Report Type: URL Security Analysis'])
    writer.writerow(['Base URL', base_url])
    writer.writerow(['Date', ''])  # You could add datetime.now() here
    writer.writerow([])  # Empty row
    
    # Write vulnerability summary
    writer.writerow(['Vulnerability Summary'])
    writer.writerow(['Type', 'Count'])
    writer.writerow(['SQL Injection', len(analysis_results.get('sql_injection', []))])
    writer.writerow(['Cross-Site Scripting (XSS)', len(analysis_results.get('xss', []))])
    writer.writerow(['Command Injection', len(analysis_results.get('command_injection', []))])
    writer.writerow(['Open Redirect', len(analysis_results.get('open_redirect', []))])
    writer.writerow(['Total URLs Scanned', len(discovered_urls)])
    writer.writerow([])  # Empty row
    
    # Write SQL Injection vulnerabilities
    if analysis_results.get('sql_injection'):
        writer.writerow(['SQL Injection Vulnerabilities'])
        writer.writerow(['URL', 'Parameter', 'Value'])
        for item in analysis_results.get('sql_injection'):
            writer.writerow([item['url'], item['parameter'], item['value']])
        writer.writerow([])  # Empty row
    
    # Write XSS vulnerabilities
    if analysis_results.get('xss'):
        writer.writerow(['Cross-Site Scripting Vulnerabilities'])
        writer.writerow(['URL', 'Parameter', 'Value'])
        for item in analysis_results.get('xss'):
            writer.writerow([item['url'], item['parameter'], item['value']])
        writer.writerow([])  # Empty row
    
    # Write Command Injection vulnerabilities
    if analysis_results.get('command_injection'):
        writer.writerow(['Command Injection Vulnerabilities'])
        writer.writerow(['URL', 'Parameter', 'Value'])
        for item in analysis_results.get('command_injection'):
            writer.writerow([item['url'], item['parameter'], item['value']])
        writer.writerow([])  # Empty row
    
    # Write Open Redirect vulnerabilities
    if analysis_results.get('open_redirect'):
        writer.writerow(['Open Redirect Vulnerabilities'])
        writer.writerow(['URL', 'Parameter', 'Value', 'External'])
        for item in analysis_results.get('open_redirect'):
            writer.writerow([item['url'], item['parameter'], item['value'], 'Yes' if item.get('is_external') else 'No'])
        writer.writerow([])  # Empty row
    
    # Write all discovered URLs
    writer.writerow(['All Discovered URLs'])
    writer.writerow(['URL'])
    for url in discovered_urls:
        writer.writerow([url])
    
    # Set the file pointer to the beginning of the file
    output.seek(0)
    
    # Create a response with the CSV file
    filename = f"security_scan_{base_url.replace('://', '_').replace('/', '_').replace('.', '_')}.csv"
    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@app.route('/crawl', methods=['POST'])
def crawl():
    """API endpoint for AJAX to start crawling."""
    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid request data'})
        
    base_url = data.get('base_url', '').strip()
    
    # Basic URL validation
    if not base_url:
        return jsonify({'status': 'error', 'message': 'Please enter a URL'})
        
    # Check if URL starts with http:// or https://
    if not (base_url.startswith('http://') or base_url.startswith('https://')):
        base_url = 'https://' + base_url
        
    # Store the base URL in session for potential use later
    session['base_url'] = base_url
    
    try:
        # Crawl the website to get all URLs
        logger.debug(f"Starting crawl of {base_url}")
        discovered_urls = crawl_website(base_url, custom_sitemap_urls=[])
        
        if not discovered_urls:
            return jsonify({'status': 'error', 'message': 'No URLs were discovered. Please check the URL and try again.'})
            
        # Analyze the discovered URLs for potential vulnerabilities
        logger.debug(f"Analyzing {len(discovered_urls)} discovered URLs")
        analysis_results = analyze_urls(discovered_urls)
        
        # Store the results in session for display
        session['analysis_results'] = analysis_results
        session['total_urls'] = len(discovered_urls)
        session['discovered_urls'] = discovered_urls
        
        return jsonify({
            'status': 'success', 
            'message': 'Crawling and analysis complete',
            'redirect': url_for('results')
        })
        
    except Exception as e:
        logger.error(f"Error during crawling or analysis: {str(e)}")
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'})

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    return render_template('error.html', error='Server error'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
