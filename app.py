from flask import Flask, render_template_string, request, jsonify
import requests
from bs4 import BeautifulSoup
import socket
import ssl
import whois
from datetime import datetime
import validators
from urllib.parse import urlparse
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string(open('templates/index.html').read())

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url
    
    if not validators.url(url):
        return jsonify({'error': 'Invalid URL format'}), 400
    
    try:
        domain = url.split('//')[1].split('/')[0]
        
        try:
            ip_address = socket.gethostbyname(domain)
        except socket.gaierror:
            ip_address = "Could not resolve IP"
        
        website_info = analyze_website(url)
        ports_info = scan_ports(domain)
        os_info = detect_os(ip_address) if ip_address != "Could not resolve IP" else {"os": "Unknown"}
        
        results = {
            'url': url,
            'domain': domain,
            'ip_address': ip_address,
            'website_info': website_info,
            'ports_info': ports_info,
            'os_info': os_info,
            'is_scam': check_for_scam(url, website_info)
        }
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

def analyze_website(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10, verify=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        meta_tags = {}
        for meta in soup.find_all('meta'):
            if 'name' in meta.attrs:
                meta_tags[meta.attrs['name']] = meta.attrs.get('content', '')
        
        forms = []
        for form in soup.find_all('form'):
            forms.append({
                'action': form.attrs.get('action', ''),
                'method': form.attrs.get('method', 'get').upper(),
                'inputs': [input.attrs.get('name', '') for input in form.find_all('input')]
            })
        
        ssl_info = check_ssl(url)
        domain_info = whois_lookup(url)
        
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'title': soup.title.string if soup.title else None,
            'meta_tags': meta_tags,
            'forms': forms,
            'ssl_info': ssl_info,
            'domain_info': domain_info,
            'content': soup.get_text()
        }
    except Exception as e:
        return {'error': str(e)}

def check_ssl(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                is_valid = datetime.now() < not_after
                
                return {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'notAfter': cert.get('notAfter', 'Unknown'),
                    'is_valid': is_valid,
                    'expires_in': (not_after - datetime.now()).days
                }
    except Exception as e:
        return {'error': str(e)}

def whois_lookup(url):
    try:
        domain = urlparse(url).netloc
        whois_info = whois.whois(domain)
        return {
            'registrar': whois_info.registrar,
            'creation_date': str(whois_info.creation_date),
            'expiration_date': str(whois_info.expiration_date),
            'name_servers': list(whois_info.name_servers)
        }
    except Exception as e:
        return {'error': str(e)}

def scan_ports(domain):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
    open_ports = []
    
    try:
        ip_address = socket.gethostbyname(domain)
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            
            if result == 0:
                service = socket.getservbyport(port, 'tcp') if port <= 1024 else 'Unknown'
                open_ports.append({
                    'port': port,
                    'service': service,
                    'status': 'Open'
                })
        
        return open_ports
    except Exception:
        return []

def detect_os(ip):
    try:
        response = os.popen(f"ping -c 1 {ip}").read()
        if "ttl=128" in response.lower():
            return {"os": "Windows"}
        elif "ttl=64" in response.lower():
            return {"os": "Linux/Unix"}
        else:
            return {"os": "Unknown"}
    except Exception:
        return {"os": "Unknown"}

def check_for_scam(url, website_info):
    scam_keywords = [
        'login', 'account', 'verify', 'password', 'bank', 
        'paypal', 'amazon', 'ebay', 'urgent', 'security',
        'alert', 'suspended', 'limited', 'verify', 'click'
    ]
    
    url_lower = url.lower()
    if any(keyword in url_lower for keyword in scam_keywords):
        return True
    
    if 'content' in website_info:
        content_lower = website_info['content'].lower()
        if any(keyword in content_lower for keyword in scam_keywords):
            return True
    
    return False

if __name__ == '__main__':
    app.run(debug=True)