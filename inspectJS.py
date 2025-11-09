#!/usr/bin/env python3
"""
inspectJS - Advanced JavaScript File Discovery and Analysis Tool
Author: mitsec (x.com/ynsmroztas)
"""

import re
import sys
import argparse
import requests
from urllib.parse import urljoin, urlparse, parse_qs
import json
from collections import defaultdict
import time
import os
import concurrent.futures
from bs4 import BeautifulSoup
import urllib3
import ssl

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class JSSpiderAnalyzer:
    def __init__(self, verify_ssl=False):
        self.verify_ssl = verify_ssl
        self.patterns = {
            'api_keys': [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,60})["\']',
                r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,60})["\']',
                r'secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,60})["\']',
                r'key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,60})["\']',
            ],
            'jwt_tokens': [
                r'eyJhbGciOiJ[^\s"\']+',
                r'["\']eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+["\']',
            ],
            'passwords': [
                r'password["\']?\s*[:=]\s*["\']([^"\'\s]{3,50})["\']',
                r'pass["\']?\s*[:=]\s*["\']([^"\'\s]{3,50})["\']',
                r'pwd["\']?\s*[:=]\s*["\']([^"\'\s]{3,50})["\']',
                r'psw["\']?\s*[:=]\s*["\']([^"\'\s]{3,50})["\']',
            ],
            'endpoints': [
                r'["\'](https?://[^"\']+?/api/[^"\']*?)["\']',
                r'["\'](/api/[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/v[0-9]/[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/graphql[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/rest/[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/auth[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/login[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/register[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/user[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/admin[^"\']*?)["\']',
            ],
            'aws_keys': [
                r'AKIA[0-9A-Z]{16}',
                r'aws[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([^"\']+?)["\']',
                r'aws[_-]?secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+?)["\']',
            ],
            'database_urls': [
                r'mongodb[+]srv://[^"\'\s]+',
                r'postgresql://[^"\'\s]+',
                r'mysql://[^"\'\s]+',
                r'redis://[^"\'\s]+',
                r'database["\']?\s*[:=]\s*["\']([^"\']+?)["\']',
            ],
            'emails': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            ],
            'ip_addresses': [
                # Strict IP validation: matches only valid IPs (0-255 per octet)
                # Uses negative lookbehind/lookahead to avoid SVG paths (e.g., M42.06.6.16)
                # Each octet: 25[0-5] (250-255) | 2[0-4][0-9] (200-249) | [01]?[0-9][0-9]? (0-199)
                r'(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9.])',
            ]
        }
        
        self.critical_endpoints = [
            'login', 'register', 'auth', 'password', 'reset', 'admin',
            'user', 'account', 'profile', 'payment', 'credit', 'bank',
            'secret', 'key', 'token', 'oauth', 'callback', 'api'
        ]
        
        self.js_patterns = [
            r'src=["\']([^"\']*?\.js(?:\?[^"\']*)?)["\']',
            r'<script[^>]*src=["\']([^"\']*?\.js(?:\?[^"\']*)?)["\']',
            r'import[^;]+from["\']([^"\']*?\.js)["\']',
            r'require\(["\']([^"\']*?\.js)["\']',
            r'["\']([^"\']*?\.js)["\']',
        ]
        
        self.discovered_js = set()
        self.analyzed_urls = set()
        self.results = defaultdict(list)
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def print_header(self):
        """Print tool header"""
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("┌──────────────────────────────────────────────────────────────┐")
        print("│                   inspectJS powered by mitsec                │")
        print("│                     (x.com/ynsmroztas)                       │")
        print("└──────────────────────────────────────────────────────────────┘")
        print(f"{Colors.END}")

    def discover_js_files(self, base_url):
        """Discover JS files from homepage and other pages"""
        print(f"{Colors.BLUE}[*]{Colors.END} Discovering JS files: {Colors.CYAN}{base_url}{Colors.END}")
        
        discovered_urls = set()
        
        try:
            # Get main page
            response = self.session.get(base_url, timeout=10)
            response.raise_for_status()
            
            # Find JS files from HTML
            js_files = self.extract_js_from_html(response.text, base_url)
            discovered_urls.update(js_files)
            
            # Find additional JS links in content
            additional_js = self.find_js_in_content(response.text, base_url)
            discovered_urls.update(additional_js)
            
            # Check sitemap or robots.txt
            robots_js = self.check_robots_txt(base_url)
            discovered_urls.update(robots_js)
            
        except requests.exceptions.SSLError as e:
            print(f"{Colors.YELLOW}[!]{Colors.END} SSL Error: {e}")
            if not self.verify_ssl:
                print(f"{Colors.BLUE}[*]{Colors.END} Retrying with SSL verification disabled...")
                self.session.verify = False
                return self.discover_js_files(base_url)
        except Exception as e:
            print(f"{Colors.RED}[!]{Colors.END} Discovery error: {e}")
        
        return discovered_urls

    def extract_js_from_html(self, html_content, base_url):
        """Extract JS files from HTML"""
        js_files = set()
        
        try:
            # BeautifulSoup parsing
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find script tags
            for script in soup.find_all('script'):
                src = script.get('src')
                if src and '.js' in src:
                    full_url = urljoin(base_url, src)
                    js_files.add(full_url)
            
            # Find JS in links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if '.js' in href:
                    full_url = urljoin(base_url, href)
                    js_files.add(full_url)
                    
        except Exception as e:
            print(f"{Colors.RED}[!]{Colors.END} HTML parsing error: {e}")
        
        return js_files

    def find_js_in_content(self, content, base_url):
        """Find JS references in content"""
        js_files = set()
        
        for pattern in self.js_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                js_path = match.group(1)
                if js_path and '.js' in js_path:
                    full_url = urljoin(base_url, js_path)
                    js_files.add(full_url)
        
        return js_files

    def check_robots_txt(self, base_url):
        """Find JS files from robots.txt"""
        js_files = set()
        
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=5)
            
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if 'Disallow:' in line or 'Allow:' in line:
                        path = line.split(':')[1].strip()
                        if '.js' in path:
                            full_url = urljoin(base_url, path)
                            js_files.add(full_url)
        except:
            pass
        
        return js_files

    def fetch_js_content(self, url):
        """Download JS file content"""
        if url in self.analyzed_urls:
            return None
            
        self.analyzed_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            # Only analyze JavaScript files
            content_type = response.headers.get('content-type', '')
            if 'javascript' in content_type or url.endswith('.js') or '.js?' in url:
                return response.text
            else:
                print(f"{Colors.YELLOW}[!]{Colors.END} Not a JavaScript file: {url}")
                return None
                
        except requests.exceptions.SSLError as e:
            print(f"{Colors.YELLOW}[!]{Colors.END} SSL Error for {url}: {e}")
            if not self.verify_ssl:
                print(f"{Colors.BLUE}[*]{Colors.END} Retrying with SSL verification disabled...")
                self.session.verify = False
                return self.fetch_js_content(url)
        except Exception as e:
            print(f"{Colors.RED}[!]{Colors.END} Download error {url}: {e}")
            return None

    def extract_http_requests_advanced(self, content):
        """Advanced HTTP request analysis"""
        requests_found = []
        
        # Fetch API patterns
        fetch_patterns = [
            r'fetch\([\s]*["\']([^"\']+?)["\'][\s]*(?:,[\s]*({[^}]+?(?:{[^}]*?}[^}]*?)?}))?[\s]*\)',
            r'fetch\([\s]*`([^`]+?)`[\s]*(?:,[\s]*({[^}]+?(?:{[^}]*?}[^}]*?)?}))?[\s]*\)',
        ]
        
        for pattern in fetch_patterns:
            matches = re.finditer(pattern, content, re.DOTALL)
            for match in matches:
                url = match.group(1).strip()
                options = match.group(2) if match.group(2) else None
                
                method = 'GET'
                headers = {}
                body = None
                
                if options:
                    method_match = re.search(r'method[\s]*:[\s]*["\']([^"\']+?)["\']', options, re.IGNORECASE)
                    if method_match:
                        method = method_match.group(1).upper()
                
                request_info = {
                    'type': 'fetch',
                    'method': method,
                    'url': url,
                    'full_match': match.group(0)[:200] + '...' if len(match.group(0)) > 200 else match.group(0)
                }
                requests_found.append(request_info)
        
        # Axios patterns
        axios_patterns = [
            r'axios\.(get|post|put|delete|patch)\([\s]*["\']([^"\']+?)["\']',
            r'axios\([\s]*{[\s]*method[\s]*:[\s]*["\'](GET|POST|PUT|DELETE|PATCH)["\'][^}]+url[\s]*:[\s]*["\']([^"\']+?)["\']',
        ]
        
        for pattern in axios_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) == 2:
                    method = match.group(1).upper()
                    url = match.group(2)
                else:
                    method = match.group(2).upper() if match.group(2) else 'GET'
                    url = match.group(1)
                
                request_info = {
                    'type': 'axios',
                    'method': method,
                    'url': url,
                }
                requests_found.append(request_info)
        
        # XMLHttpRequest patterns
        xhr_pattern = r'\.open\([\s]*["\'](GET|POST|PUT|DELETE)["\'][\s]*,[\s]*["\']([^"\']+?)["\']'
        matches = re.finditer(xhr_pattern, content)
        for match in matches:
            request_info = {
                'type': 'xhr',
                'method': match.group(1),
                'url': match.group(2),
            }
            requests_found.append(request_info)
        
        return requests_found

    def analyze_parameters(self, url):
        """Analyze URL parameters"""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            path_params = re.findall(r'/:([a-zA-Z_]\w*)', parsed.path)
            
            return {
                'query_params': list(query_params.keys()),
                'path_params': path_params,
            }
        except:
            return {'query_params': [], 'path_params': []}

    def is_critical_endpoint(self, url):
        """Check if endpoint is critical"""
        url_lower = url.lower()
        for critical in self.critical_endpoints:
            if critical in url_lower:
                return True, critical
        return False, None

    def scan_js_content(self, content, url):
        """Scan JS content for sensitive data"""
        local_results = defaultdict(list)
        
        # Pattern scanning
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    value = match.group(1) if match.groups() else match.group(0)
                    
                    local_results[category].append({
                        'value': value,
                        'source_url': url,
                        'context': content[max(0, match.start()-50):match.end()+50],
                    })
        
        # HTTP request analysis
        http_requests = self.extract_http_requests_advanced(content)
        for req in http_requests:
            param_analysis = self.analyze_parameters(req['url'])
            req.update(param_analysis)
            
            is_critical, critical_type = self.is_critical_endpoint(req['url'])
            req['is_critical'] = is_critical
            req['critical_type'] = critical_type
            req['source_url'] = url
            
            local_results['http_requests'].append(req)
        
        return local_results

    def analyze_discovered_js(self, js_urls, max_workers=5):
        """Analyze discovered JS files"""
        print(f"{Colors.BLUE}[*]{Colors.END} Analyzing {Colors.CYAN}{len(js_urls)}{Colors.END} JS files...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.analyze_single_js, url): url 
                for url in js_urls
            }
            
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"{Colors.RED}[!]{Colors.END} Analysis error {url}: {e}")

    def analyze_single_js(self, url):
        """Analyze single JS file"""
        print(f"{Colors.BLUE}[>]{Colors.END} Downloading: {Colors.CYAN}{url}{Colors.END}")
        
        content = self.fetch_js_content(url)
        if not content:
            return
        
        print(f"{Colors.GREEN}[+]{Colors.END} Analyzing: {Colors.CYAN}{url}{Colors.END} ({Colors.YELLOW}{len(content):,}{Colors.END} chars)")
        
        results = self.scan_js_content(content, url)
        
        # Add results to global results
        for category, items in results.items():
            self.results[category].extend(items)

    def print_comprehensive_report(self, base_url):
        """Print comprehensive report"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'═'*70}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}                  COMPREHENSIVE ANALYSIS REPORT{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'═'*70}{Colors.END}")
        print(f"{Colors.WHITE}🔗 Target Site: {Colors.CYAN}{base_url}{Colors.END}")
        print(f"{Colors.WHITE}📅 Scan Date: {Colors.CYAN}{time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
        print(f"{Colors.WHITE}📁 Discovered JS Files: {Colors.CYAN}{len(self.analyzed_urls)}{Colors.END}")
        print(f"{Colors.CYAN}{'─'*70}{Colors.END}")
        
        # Discovered JS files
        if self.analyzed_urls:
            print(f"\n{Colors.GREEN}📂 DISCOVERED JS FILES ({len(self.analyzed_urls)}):{Colors.END}")
            for i, url in enumerate(list(self.analyzed_urls)[:20], 1):
                print(f"   {Colors.WHITE}{i:2d}. {Colors.CYAN}{url}{Colors.END}")
        
        # Critical findings
        self.print_critical_findings()
        
        # HTTP requests
        self.print_http_requests()
        
        # Other findings
        self.print_other_findings()
        
        # Summary
        self.print_summary()

    def print_critical_findings(self):
        """Print critical findings with color coding"""
        critical_categories = {
            'passwords': Colors.RED,
            'aws_keys': Colors.RED, 
            'database_urls': Colors.RED,
            'api_keys': Colors.YELLOW,
            'jwt_tokens': Colors.YELLOW
        }
        
        found_critical = False
        
        for category, color in critical_categories.items():
            if self.results.get(category):
                found_critical = True
                icon = "🔴" if color == Colors.RED else "🟡"
                
                print(f"\n{color}{icon} CRITICAL {category.upper()} FOUND ({len(self.results[category])}):{Colors.END}")
                for i, item in enumerate(self.results[category][:10], 1):
                    print(f"   {Colors.WHITE}{i:2d}. {color}{item['value']}{Colors.END}")
                    print(f"       {Colors.WHITE}📎 Source: {Colors.CYAN}{item['source_url']}{Colors.END}")
                    if len(item['value']) < 50:  # Only show context for shorter values
                        print(f"       {Colors.WHITE}📝 Context: {Colors.YELLOW}...{item['context']}...{Colors.END}")
        
        if not found_critical:
            print(f"\n{Colors.GREEN}✅ No critical secrets found in JS files{Colors.END}")

    def print_http_requests(self):
        """Print HTTP requests with color coding"""
        if self.results.get('http_requests'):
            critical_requests = [r for r in self.results['http_requests'] if r.get('is_critical')]
            normal_requests = [r for r in self.results['http_requests'] if not r.get('is_critical')]
            
            if critical_requests:
                print(f"\n{Colors.RED}🚨 CRITICAL ENDPOINT REQUESTS ({len(critical_requests)}):{Colors.END}")
                for i, req in enumerate(critical_requests[:10], 1):
                    print(f"\n   {Colors.WHITE}{i:2d}. {Colors.RED}{req['method']} {req['url']}{Colors.END}")
                    print(f"       {Colors.WHITE}📎 Source: {Colors.CYAN}{req['source_url']}{Colors.END}")
                    print(f"       {Colors.WHITE}🔍 Type: {Colors.RED}{req.get('critical_type', 'N/A')}{Colors.END}")
                    
                    if req.get('query_params'):
                        print(f"       {Colors.WHITE}📋 Query Parameters: {Colors.YELLOW}{', '.join(req['query_params'])}{Colors.END}")
                    if req.get('path_params'):
                        print(f"       {Colors.WHITE}🛣️  Path Parameters: {Colors.YELLOW}{', '.join(req['path_params'])}{Colors.END}")
            
            if normal_requests:
                print(f"\n{Colors.BLUE}🌐 OTHER HTTP REQUESTS ({len(normal_requests)}):{Colors.END}")
                for i, req in enumerate(normal_requests[:5], 1):
                    print(f"   {Colors.WHITE}{i:2d}. {Colors.BLUE}{req['method']} {req['url']}{Colors.END}")
                    if req.get('query_params'):
                        print(f"       {Colors.WHITE}📋 Parameters: {Colors.YELLOW}{', '.join(req['query_params'])}{Colors.END}")
        else:
            print(f"\n{Colors.BLUE}ℹ️  No HTTP requests found in JS files{Colors.END}")

    def print_other_findings(self):
        """Print other findings"""
        other_categories = ['emails', 'ip_addresses', 'endpoints']
        found_other = False
        
        for category in other_categories:
            if self.results.get(category):
                found_other = True
                color = Colors.BLUE
                icon = "📧" if category == 'emails' else "🌐" if category == 'ip_addresses' else "🔗"
                
                print(f"\n{color}{icon} {category.upper()} FOUND ({len(self.results[category])}):{Colors.END}")
                for i, item in enumerate(self.results[category][:5], 1):
                    print(f"   {Colors.WHITE}{i:2d}. {Colors.CYAN}{item['value']}{Colors.END}")
                    print(f"       {Colors.WHITE}📎 Source: {Colors.CYAN}{item['source_url']}{Colors.END}")

    def print_summary(self):
        """Print colored summary"""
        total_findings = sum(len(items) for items in self.results.values())
        critical_requests = len([r for r in self.results.get('http_requests', []) if r.get('is_critical')])
        total_critical = sum(len(self.results.get(cat, [])) for cat in ['api_keys', 'jwt_tokens', 'passwords', 'aws_keys', 'database_urls'])
        
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'═'*70}{Colors.END}")
        print(f"{Colors.WHITE}{Colors.BOLD}                    SCAN SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'═'*70}{Colors.END}")
        print(f"   {Colors.WHITE}📁 Discovered JS Files: {Colors.GREEN}{len(self.analyzed_urls)}{Colors.END}")
        print(f"   {Colors.WHITE}🔴 Critical Secrets: {Colors.RED if total_critical > 0 else Colors.GREEN}{total_critical}{Colors.END}")
        print(f"   {Colors.WHITE}🌐 HTTP Requests: {Colors.BLUE}{len(self.results.get('http_requests', []))}{Colors.END}")
        print(f"   {Colors.WHITE}🚨 Critical Endpoints: {Colors.RED if critical_requests > 0 else Colors.GREEN}{critical_requests}{Colors.END}")
        print(f"   {Colors.WHITE}📊 Total Findings: {Colors.CYAN}{total_findings}{Colors.END}")
        
        # Security assessment
        if total_critical > 0 or critical_requests > 0:
            print(f"   {Colors.RED}⚡ SECURITY RISK: {Colors.BOLD}HIGH{Colors.END}")
        elif total_findings > 0:
            print(f"   {Colors.YELLOW}⚡ SECURITY RISK: {Colors.BOLD}MEDIUM{Colors.END}")
        else:
            print(f"   {Colors.GREEN}⚡ SECURITY RISK: {Colors.BOLD}LOW{Colors.END}")
            
        print(f"{Colors.CYAN}{'═'*70}{Colors.END}")

    def save_comprehensive_report(self, base_url, filename):
        """Save comprehensive report to file"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"inspectJS Analysis Report\n")
            f.write(f"Target: {base_url}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Discovered JS Files: {len(self.analyzed_urls)}\n")
            f.write("="*70 + "\n\n")
            
            f.write("DISCOVERED JS FILES:\n")
            for url in self.analyzed_urls:
                f.write(f"- {url}\n")
            f.write("\n")
            
            for category, items in self.results.items():
                if items:
                    f.write(f"{category.upper()}:\n")
                    for item in items:
                        if isinstance(item, dict):
                            f.write(f"  - {item.get('value', str(item))}\n")
                            f.write(f"    Source: {item.get('source_url', 'N/A')}\n")
                        else:
                            f.write(f"  - {str(item)}\n")
                    f.write("\n")

def main():
    spider = JSSpiderAnalyzer()
    spider.print_header()
    
    parser = argparse.ArgumentParser(description='inspectJS - JavaScript File Discovery and Analysis')
    parser.add_argument('-u', '--url', required=True, help='Target website URL')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('-d', '--depth', type=int, default=1, help='Discovery depth (1-3)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--verify-ssl', action='store_true', help='Enable SSL verification')
    
    args = parser.parse_args()
    
    spider = JSSpiderAnalyzer(verify_ssl=args.verify_ssl)
    
    print(f"{Colors.BLUE}[*]{Colors.END} Target Site: {Colors.CYAN}{args.url}{Colors.END}")
    print(f"{Colors.BLUE}[*]{Colors.END} Discovery Depth: {Colors.CYAN}{args.depth}{Colors.END}")
    print(f"{Colors.BLUE}[*]{Colors.END} Threads: {Colors.CYAN}{args.threads}{Colors.END}")
    print(f"{Colors.BLUE}[*]{Colors.END} SSL Verification: {Colors.CYAN}{'Enabled' if args.verify_ssl else 'Disabled'}{Colors.END}")
    print(f"\n{Colors.CYAN}{'─'*50}{Colors.END}")
    
    # Discover JS files
    print(f"{Colors.BLUE}[*]{Colors.END} Discovering JS files...")
    js_files = spider.discover_js_files(args.url)
    
    if not js_files:
        print(f"{Colors.RED}[!]{Colors.END} No JS files found!")
        return
    
    print(f"{Colors.GREEN}[+]{Colors.END} {Colors.CYAN}{len(js_files)}{Colors.END} JS files discovered")
    
    # Analyze JS files
    print(f"{Colors.BLUE}[*]{Colors.END} Analyzing JS files...")
    spider.analyze_discovered_js(js_files, max_workers=args.threads)
    
    # Generate report
    spider.print_comprehensive_report(args.url)
    
    # Save to file
    if args.output:
        spider.save_comprehensive_report(args.url, args.output)
        print(f"{Colors.GREEN}[+]{Colors.END} Full report saved to '{Colors.CYAN}{args.output}{Colors.END}'")

if __name__ == "__main__":
    main()