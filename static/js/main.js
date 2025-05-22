// Main JavaScript for URL Security Scanner

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.forEach(function(tooltipTriggerEl) {
        new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Form validation
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });

    // Add URL protocol if missing
    const urlInput = document.getElementById('base_url');
    if (urlInput) {
        urlInput.addEventListener('blur', function() {
            const url = urlInput.value.trim();
            if (url && !url.startsWith('http://') && !url.startsWith('https://')) {
                urlInput.value = 'https://' + url;
            }
        });
    }

    // Handle scan form submission with AJAX
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function(event) {
            event.preventDefault();
            
            // Get form data
            const baseUrl = document.getElementById('base_url').value.trim();
            
            // Basic validation
            if (!baseUrl) {
                showError('Please enter a URL');
                return;
            }
            
            // Show loading indicator
            showLoading();
            
            // Send AJAX request
            fetch('/crawl', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    base_url: baseUrl
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    // Simulate progress for better UX
                    simulateProgress(function() {
                        // Redirect to results page
                        window.location.href = data.redirect;
                    });
                } else {
                    // Show error
                    hideLoading();
                    showError(data.message);
                }
            })
            .catch(error => {
                // Handle error
                hideLoading();
                showError('An error occurred: ' + error);
            });
        });
    }

    // Toggle visibility of sections with large tables
    const toggleButtons = document.querySelectorAll('.toggle-section');
    toggleButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                const isVisible = targetElement.style.display !== 'none';
                targetElement.style.display = isVisible ? 'none' : 'block';
                
                // Update button text
                this.innerHTML = isVisible ? 
                    '<i class="fas fa-plus me-1"></i> Show Details' : 
                    '<i class="fas fa-minus me-1"></i> Hide Details';
            }
        });
    });

    // Truncate long URLs in tables with a "show more" option
    const longUrls = document.querySelectorAll('.truncate-url');
    longUrls.forEach(function(element) {
        const fullUrl = element.textContent;
        if (fullUrl.length > 60) {
            const truncated = fullUrl.substring(0, 60) + '...';
            
            const span = document.createElement('span');
            span.textContent = truncated;
            
            const showMoreBtn = document.createElement('button');
            showMoreBtn.className = 'btn btn-sm btn-link p-0 ms-1';
            showMoreBtn.textContent = 'Show More';
            
            showMoreBtn.addEventListener('click', function() {
                if (span.textContent === truncated) {
                    span.textContent = fullUrl;
                    this.textContent = 'Show Less';
                } else {
                    span.textContent = truncated;
                    this.textContent = 'Show More';
                }
            });
            
            element.innerHTML = '';
            element.appendChild(span);
            element.appendChild(showMoreBtn);
        }
    });
});

// Function to show loading indicator
function showLoading() {
    // Hide error container if visible
    document.getElementById('error-container').classList.add('d-none');
    
    // Show loading container
    document.getElementById('loading-container').classList.remove('d-none');
    
    // Disable scan button and URL input
    document.getElementById('scan-button').disabled = true;
    document.getElementById('base_url').disabled = true;
    
    // Reset progress bar
    const progressBar = document.getElementById('progress-bar');
    progressBar.style.width = '0%';
    progressBar.setAttribute('aria-valuenow', 0);
}

// Function to hide loading indicator
function hideLoading() {
    // Hide loading container
    document.getElementById('loading-container').classList.add('d-none');
    
    // Enable scan button and URL input
    document.getElementById('scan-button').disabled = false;
    document.getElementById('base_url').disabled = false;
}

// Function to show error message
function showError(message) {
    const errorContainer = document.getElementById('error-container');
    const errorMessage = document.getElementById('error-message');
    
    errorMessage.textContent = message;
    errorContainer.classList.remove('d-none');
}

// Function to simulate progress for better UX
function simulateProgress(callback) {
    const progressBar = document.getElementById('progress-bar');
    const statusMessage = document.getElementById('status-message');
    let progress = 5;
    
    // Update status message
    statusMessage.textContent = 'Crawling website...';
    
    const interval = setInterval(function() {
        // Simulate progress
        progress += Math.random() * 10;
        
        // Update progress bar
        if (progress < 90) {
            progressBar.style.width = progress + '%';
            progressBar.setAttribute('aria-valuenow', progress);
            
            // Update status message at certain points
            if (progress > 30 && progress < 35) {
                statusMessage.textContent = 'Discovering links...';
            } else if (progress > 60 && progress < 65) {
                statusMessage.textContent = 'Analyzing URLs for vulnerabilities...';
            }
        } else {
            // Finish progress
            clearInterval(interval);
            progressBar.style.width = '100%';
            progressBar.setAttribute('aria-valuenow', 100);
            statusMessage.textContent = 'Analysis complete! Redirecting...';
            
            // Wait a moment before callback
            setTimeout(callback, 500);
        }
    }, 300);
}
