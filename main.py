import socket
from urllib.parse import urlparse
from flask import Flask, request, redirect, url_for, render_template
from flask_limiter import Limiter  # type: ignore
from flask_limiter.util import get_remote_address  # type: ignore
import os
from datetime import datetime
from playwright.sync_api import sync_playwright  # type: ignore
import re

app = Flask(__name__)

limiter = Limiter(
    get_remote_address, 
    app=app,
    default_limits=["5 per minute"]  
)


def check_url(url):
    return re.match(r'^https?://', url) is None


def is_local_ip(url):
    
    if "http://127.0.0.1".lower() in url.lower() or "http://localhost".lower() in url.lower():
        return True


    local_ip_regex = r"^http://(192\.168|10|172\.16|172\.17|172\.18|172\.19|172\.20|172\.21|172\.22|172\.23|172\.24|172\.25|172\.26|172\.27|172\.28|172\.29|172\.30|172\.31)\.\d{1,3}\.\d{1,3}$"
    if re.match(local_ip_regex, url):
        return True
    
    return False


def has_malicious_extension(url):
    malicious_extensions = ['.exe', '.bat', '.cmd', '.msi', '.scr', '.pif', '.vbs', '.js','.bin']
    return any(url.endswith(ext) for ext in malicious_extensions)


def capture_screenshot(url):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url)

            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"screenshot_{timestamp}.png"

            
            screenshot_path = os.path.join('static', 'screenshots', filename)
            os.makedirs(os.path.join('static', 'screenshots'), exist_ok=True)
            page.screenshot(path=screenshot_path)
            browser.close()
            return filename
    except Exception as e:
        return f"Hata: {str(e)}"

def is_resolved_local_ip(url):
    try:
        
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        
        if not domain:
            return True 
        
        ip_address = socket.gethostbyname(domain)
        
        if ip_address.startswith('127.') or ip_address.startswith('10.') or ip_address.startswith('192.168.') or ip_address.startswith('172.'):
            return True
        return False
    except Exception:
        return True  


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/capture', methods=['POST'])
@limiter.limit("5 per minute") 
def capture():
    url = request.form.get('url')

    if "file://" in url or "file:\\" in url:
        user_ip = request.remote_addr
        user_agent = request.user_agent
        print(f"Potentially dangerous access attempt detected.")
        print(f"User IP: {user_ip}")
        print(f"User Agent: {user_agent}")
        print(f"Attempted URL: {url}")
        return render_template('index.html', error_message="File URLs are not supported.")

    if is_local_ip(url) or is_resolved_local_ip(url):
        user_ip = request.remote_addr
        user_agent = request.user_agent
        print(f"Potentially dangerous access attempt detected.")
        print(f"User IP: {user_ip}")
        print(f"User Agent: {user_agent}")
        print(f"Attempted URL: {url}")
        return render_template('index.html', error_message="Access to local IP addresses is not allowed!")
        

    if check_url(url):
        return render_template('index.html', error_message="Invalid URL format. Please enter a valid URL.")
        
    if has_malicious_extension(url):
        return render_template('index.html', error_message="Malicious file extension detected! Access denied.")


    if url:
        screenshot_filename = capture_screenshot(url)
        return render_template('index.html', screenshot_filename=screenshot_filename)

    return 'No URL provided!', 400
if __name__ == '__main__':
    app.run(debug=True)
