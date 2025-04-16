#!/usr/bin/env python3
"""
ULTIMATE VULNERABILITY SCANNER PRO
Enterprise-grade security assessment platform with real-time monitoring,
advanced visualization, and comprehensive reporting.
"""

import shutil
import os
import sys
import subprocess
import aiohttp
import asyncio
import logging
import json
from rich.progress import TimeElapsedColumn
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Union, Any
import re
import argparse
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict
import socket
import geoip2.database
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx
import squarify
import yaml
import markdown
import pdfkit
import csv
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor

# Enhanced imports for visualization and reporting
from rich import print
from rich.console import Console
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import (
    Progress, 
    BarColumn, 
    TextColumn, 
    TimeRemainingColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TimeElapsedColumn
)
from rich.live import Live
from rich.text import Text
from rich.style import Style
from rich.tree import Tree
from rich.syntax import Syntax
from rich.markdown import Markdown

# Security and networking imports
import nmap
import dns.resolver
import whois
import ssl
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import scapy.all as scapy
from scapy.layers import http

# Database and caching
import redis
import elasticsearch
from elasticsearch import helpers

# Web and API
from fastapi import FastAPI
import uvicorn
import socketio
from socketio import AsyncClient
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Template engine for report generation
from jinja2 import Environment, FileSystemLoader

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants and Configuration
class Config:
    """Centralized configuration with environment awareness"""
    
    # Directory setup
    BASE_DIR = Path(__file__).parent.resolve()
    OUTPUT_DIR = BASE_DIR / "fypoutput"
    NMAP_SCRIPT_DIR = BASE_DIR / "nmap_scripts"
    TEMPLATE_DIR = BASE_DIR / "templates"
    REPORT_TEMPLATE = TEMPLATE_DIR / "report_template.html"
    GEOIP_DB = BASE_DIR / "GeoLite2-City.mmdb"
    
    # Create required directories
    OUTPUT_DIR.mkdir(exist_ok=True)
    NMAP_SCRIPT_DIR.mkdir(exist_ok=True)
    WKHTMLTOPDF_PATH = '/usr/bin/wkhtmltopdf' 
    # API Keys and sensitive config
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
    CENSYS_API_ID = os.getenv('CENSYS_API_ID', '')
    CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET', '')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    
    # Network config
    DEFAULT_PORTS = '21,22,23,25,53,80,110,143,443,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9000,9200'
    SCAN_TIMEOUT = 600  # 10 minutes
    
    # Redis config
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_DB = int(os.getenv('REDIS_DB', 0))
    
    # Elasticsearch config
    ES_ENABLED = os.getenv('ES_ENABLED', 'false').lower() == 'true'
    ES_SCHEME = os.getenv('ES_SCHEME', 'http')
    ES_HOST = os.getenv('ES_HOST', 'localhost')
    ES_PORT = int(os.getenv('ES_PORT', 9200))
    
    # Socket.IO config
    SOCKETIO_URL = os.getenv('SOCKETIO_URL', 'http://localhost:5000')
    
    # Report formats
    REPORT_FORMATS = ['pdf', 'html', 'json', 'csv', 'xml', 'md', 'svg', 'png']
    
    @classmethod
    def validate(cls):
        """Validate configuration and dependencies"""
        if not cls.GEOIP_DB.exists():
            logger.warning(f"GeoIP database not found at {cls.GEOIP_DB}")
        
        try:
            redis.Redis(host=cls.REDIS_HOST, port=cls.REDIS_PORT, db=cls.REDIS_DB).ping()
        except redis.ConnectionError:
            logger.error(f"Could not connect to Redis at {cls.REDIS_HOST}:{cls.REDIS_PORT}")
        
        if cls.ES_ENABLED:
            try:
                es = elasticsearch.Elasticsearch([f"{cls.ES_SCHEME}://{cls.ES_HOST}:{cls.ES_PORT}"])
                try:
                    if not es.ping():
                        logger.error(f"Could not connect to Elasticsearch at {cls.ES_SCHEME}://{cls.ES_HOST}:{cls.ES_PORT}")
                except Exception as e:
                    logger.error(f"Elasticsearch ping failed: {str(e)}")
            except Exception as e:
                logger.error(f"Elasticsearch connection failed: {str(e)}")

# Initialize services
redis_client = redis.Redis(
    host=Config.REDIS_HOST,
    port=Config.REDIS_PORT,
    db=Config.REDIS_DB,
    decode_responses=True
)

es_client = None
if Config.ES_ENABLED:
    try:
        es_client = elasticsearch.Elasticsearch(
            [f"{Config.ES_SCHEME}://{Config.ES_HOST}:{Config.ES_PORT}"],
            request_timeout=30
        )
        # Test the connection
        if not es_client.ping():
            logger.warning("Elasticsearch connection failed (ping failed)")
            es_client = None
    except Exception as e:
        logger.warning(f"Elasticsearch initialization failed: {str(e)}")
        es_client = None

# Socket.IO Client
class SocketIOClient:
    """Robust Socket.IO client with reconnection and fallback"""
    
    def __init__(self):
        self.sio = AsyncClient(reconnection=True, reconnection_attempts=5)
        self.connected = False
        self.connection_failed = False
        
    async def connect(self):
        """Establish connection with error handling"""
        if self.connected or self.connection_failed:
            return
            
        try:
            await self.sio.connect(Config.SOCKETIO_URL)
            self.connected = True
            self.connection_failed = False
            logger.info("Socket.IO connection established")
            
            @self.sio.event
            async def connect_error(data):
                logger.error(f"Socket.IO connection error: {data}")
                self.connected = False
                
            @self.sio.event
            async def disconnect():
                logger.warning("Socket.IO disconnected")
                self.connected = False
                
        except Exception as e:
            logger.warning(f"Socket.IO connection failed: {str(e)}")
            self.connection_failed = True
            
    async def emit(self, event_type: str, data: Dict):
        """Emit event with graceful fallback"""
        try:
            if not self.connected:
                await self.connect()
                
            if self.connected:
                await self.sio.emit(event_type, {
                    'timestamp': datetime.now().isoformat(),
                    'data': data
                })
        except Exception as e:
            logger.debug(f"Socket.IO emit failed: {str(e)}")
            self.connected = False

# Enhanced Progress Tracker
class ScanProgress:
    """Advanced progress visualization with multiple metrics"""
    
    def __init__(self, total_tasks: int = 10):
        self.console = Console()
        self.layout = Layout()
        self._setup_layout()
        
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            TimeElapsedColumn(),
            expand=True
        )
        
        self.overall_task = self.progress.add_task("[cyan]Overall Progress", total=total_tasks)
        self.subtasks = {}
        self.metrics = {}
        
    def _setup_layout(self):
        """Configure the rich layout"""
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=7)
        )
        
        self.layout["main"].split_row(
            Layout(name="progress", ratio=2),
            Layout(name="metrics", ratio=1)
        )
        
        self.layout["header"].update(
            Panel(Text("Vulnerability Scanner Pro", justify="center", style="bold blue"))
        )
        
        self.layout["footer"].split(
            Layout(name="vulnerabilities", ratio=1),
            Layout(name="network", ratio=1)
        )
        
    def update_network_info(self, info: Dict):
        """Update network information panel"""
        network_table = Table(title="Network Information")
        network_table.add_column("Property", style="cyan")
        network_table.add_column("Value", style="magenta")
        
        for key, value in info.items():
            network_table.add_row(key, str(value))
            
        self.layout["network"].update(Panel(network_table))
        
    def update_vulnerabilities(self, vulns: List[Dict]):
        """Update vulnerabilities panel"""
        vuln_table = Table(title="Critical Vulnerabilities")
        vuln_table.add_column("Port", style="red")
        vuln_table.add_column("Service")
        vuln_table.add_column("Description")
        
        for vuln in vulns:
            if vuln['severity'] == 'critical':
                vuln_table.add_row(
                    str(vuln['port']),
                    vuln.get('service', 'unknown'),
                    vuln['output'][:50] + '...'
                )
                
        self.layout["vulnerabilities"].update(Panel(vuln_table))
        
    def update(self, message: str, increment: int = 1, metrics: Dict = None):
        """Update progress and metrics"""
        self.progress.update(self.overall_task, advance=increment, description=f"[cyan]{message}")
        
        if metrics:
            self.metrics.update(metrics)
            self._update_metrics_panel()
            
    def _update_metrics_panel(self):
        """Update the metrics display"""
        metrics_table = Table(show_header=False, box=None)
        metrics_table.add_column("Metric", style="magenta")
        metrics_table.add_column("Value", style="green")
        
        for key, value in self.metrics.items():
            metrics_table.add_row(key, str(value))
            
        self.layout["metrics"].update(
            Panel(metrics_table, title="[b]Scan Metrics")
        )
        
    def add_subtask(self, name: str, total: int):
        """Add a new subtask"""
        task_id = self.progress.add_task(f"[green]{name}", total=total)
        self.subtasks[name] = task_id
        return task_id
        
    def update_subtask(self, name: str, increment: int = 1):
        """Update a subtask"""
        if name in self.subtasks:
            self.progress.update(self.subtasks[name], advance=increment)
            
    def display(self):
        """Display the live interface"""
        self.layout["progress"].update(
            Panel(self.progress, title="[b]Scan Progress")
        )
        
        return self.layout

# Core Scanner Class
class VulnerabilityScanner:
    """Main scanner class with comprehensive capabilities"""
    
    def __init__(self):
        self.sio = SocketIOClient()
        self.nm = nmap.PortScanner()
        self.geoip_reader = None
        self.scan_id = str(uuid4())
        
        try:
            self.geoip_reader = geoip2.database.Reader(str(Config.GEOIP_DB))
        except Exception as e:
            logger.warning(f"Could not load GeoIP database: {str(e)}")
            self.geoip_reader = None
            
    async def run_scan(self, target: str, ports: str = None, intensity: str = 'normal'):
        """Main scan execution method"""
        ports = ports or Config.DEFAULT_PORTS
        scan_results = {}
        
        try:
            # Start real-time monitoring
            await self.sio.connect()
            await self.sio.emit('scan_start', {
                'scan_id': self.scan_id,
                'target': target,
                'ports': ports,
                'intensity': intensity
            })
            
            # Initialize progress tracker
            with Live(console=Console(), refresh_per_second=10) as live:
                progress = ScanProgress(total_tasks=8)
                live.update(progress.display())
                
                # Phase 1: Target Validation
                progress.update("Validating target", metrics={
                    'Target': target,
                    'Ports': ports,
                    'Intensity': intensity
                })
                
                target_info = await self._validate_target(target)
                progress.update("Target validated", 1, {
                    'Target Status': target_info.get('status', 'unknown'),
                    'Hostnames': ', '.join(target_info.get('hostnames', []))
                })
                
                # Phase 2: Port Scanning
                progress.add_subtask("Port Scanning", 100)
                port_results = await self._scan_ports(target, ports, intensity)
                progress.update("Port scan completed", 1, {
                    'Open Ports': len(port_results.get('open_ports', [])),
                    'Filtered Ports': len(port_results.get('filtered_ports', []))
                })
                
                # Phase 3: Service Detection
                progress.add_subtask("Service Detection", len(port_results.get('open_ports', [])))
                service_results = await self._detect_services(target, port_results)
                progress.update("Service detection completed", 1, {
                    'Services Found': len(service_results.get('services', []))
                })
                
                # Phase 4: Vulnerability Scanning
                progress.add_subtask("Vulnerability Scanning", len(service_results.get('services', [])))
                vuln_results = await self._scan_vulnerabilities(target, service_results)
                progress.update("Vulnerability scan completed", 1, {
                    'Vulnerabilities Found': len(vuln_results.get('vulnerabilities', []))
                })
                
                # Phase 5: Network Analysis
                progress.add_subtask("Network Analysis", 1)
                network_results = await self._analyze_network(target, vuln_results)
                progress.update("Network analysis completed", 1)
                
                # Phase 6: Reporting
                progress.add_subtask("Report Generation", len(Config.REPORT_FORMATS))
                report_paths = await self._generate_reports(target, {
                    'target_info': target_info,
                    'port_results': port_results,
                    'service_results': service_results,
                    'vulnerability_results': vuln_results,
                    'network_results': network_results
                })
                progress.update("Reports generated", 1, {
                    'Report Formats': ', '.join(report_paths.keys())
                })
                
                # Finalize
                progress.update("Scan completed successfully", 1)
                
                scan_results = {
                    'status': 'completed',
                    'scan_id': self.scan_id,
                    'results': {
                        'target_info': target_info,
                        'port_results': port_results,
                        'service_results': service_results,
                        'vulnerability_results': vuln_results,
                        'network_results': network_results
                    },
                    'reports': report_paths
                }
                
                await self.sio.emit('scan_complete', scan_results)
                
                return scan_results
                
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}", exc_info=True)
            await self.sio.emit('scan_error', {
                'scan_id': self.scan_id,
                'error': str(e)
            })
            raise
            
    async def _validate_target(self, target: str) -> Dict:
        """Validate target and gather preliminary info"""
        result = {
            'target': target,
            'status': 'unknown',
            'hostnames': [],
            'geoip': {},
            'whois': {}
        }
        
        try:
            # DNS resolution
            try:
                answers = dns.resolver.resolve(target, 'A')
                result['ip_addresses'] = [str(r) for r in answers]
                primary_ip = result['ip_addresses'][0]
                
                # Reverse DNS
                try:
                    hostnames = socket.gethostbyaddr(primary_ip)
                    result['hostnames'] = list(set(hostnames[0]))
                except socket.herror:
                    pass
                    
            except dns.resolver.NXDOMAIN:
                # Assume target is an IP address
                primary_ip = target
                result['ip_addresses'] = [target]
                
            # GeoIP lookup
            if self.geoip_reader:
                try:
                    geoip_data = self.geoip_reader.city(primary_ip)
                    result['geoip'] = {
                        'country': geoip_data.country.name,
                        'city': geoip_data.city.name,
                        'latitude': geoip_data.location.latitude,
                        'longitude': geoip_data.location.longitude,
                        'asn': geoip_data.traits.autonomous_system_number,
                        'organization': geoip_data.traits.autonomous_system_organization
                    }
                except Exception:
                    pass
                    
            # WHOIS lookup
            try:
                whois_data = whois.whois(primary_ip)
                result['whois'] = {
                    'registrar': whois_data.registrar,
                    'creation_date': str(whois_data.creation_date),
                    'updated_date': str(whois_data.updated_date),
                    'expiration_date': str(whois_data.expiration_date),
                    'name_servers': list(set(whois_data.name_servers))
                }
            except Exception:
                pass
                
            # Basic connectivity check
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)
                    s.connect((primary_ip, 80))
                result['status'] = 'responsive'
            except Exception:
                result['status'] = 'unresponsive'
                
        except Exception as e:
            logger.error(f"Target validation failed: {str(e)}")
            result['error'] = str(e)
            
        return result
        
    async def _scan_ports(self, target: str, ports: str, intensity: str) -> Dict:
        """Perform comprehensive port scanning"""
        result = {
            'open_ports': [],
            'filtered_ports': [],
            'closed_ports': [],
            'scan_stats': {}
        }
        
        try:
            # Configure scan based on intensity
            scan_args = '-sS'  # Default SYN scan
            if intensity == 'stealth':
                scan_args = '-sS -T2'
            elif intensity == 'aggressive':
                scan_args = '-sS -T4 -A'
            elif intensity == 'comprehensive':
                scan_args = '-sS -sV -sC -A -T4'
                
            logger.info(f"Scanning ports {ports} on {target} with intensity {intensity}")
            
            # Run the scan
            scan_result = self.nm.scan(
                hosts=target,
                ports=ports,
                arguments=scan_args,
                timeout=Config.SCAN_TIMEOUT
            )
            
            # Process results
            host_data = scan_result['scan'].get(target, {})
            result['scan_stats'] = scan_result['nmap']['scanstats']
            
            for port, port_data in host_data.get('tcp', {}).items():
                if port_data['state'] == 'open':
                    result['open_ports'].append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': port_data.get('name', 'unknown'),
                        'reason': port_data.get('reason', ''),
                        'product': port_data.get('product', ''),
                        'version': port_data.get('version', '')
                    })
                elif port_data['state'] == 'filtered':
                    result['filtered_ports'].append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'filtered',
                        'reason': port_data.get('reason', '')
                    })
                    
            for port, port_data in host_data.get('udp', {}).items():
                if port_data['state'] == 'open':
                    result['open_ports'].append({
                        'port': port,
                        'protocol': 'udp',
                        'state': 'open',
                        'service': port_data.get('name', 'unknown')
                    })
                    
            # TCP traceroute
            try:
                traceroute = self.nm.scan(
                    hosts=target,
                    arguments='--traceroute',
                    timeout=Config.SCAN_TIMEOUT
                )
                result['traceroute'] = traceroute['scan'][target].get('trace', {})
            except Exception as e:
                logger.warning(f"Traceroute failed: {str(e)}")
                
        except Exception as e:
            logger.error(f"Port scanning failed: {str(e)}")
            result['error'] = str(e)
            
        return result
        
    async def _detect_services(self, target: str, port_results: Dict) -> Dict:
        """Perform service detection and fingerprinting"""
        result = {
            'services': [],
            'os_info': {},
            'service_stats': {}
        }
        
        try:
            open_ports = port_results.get('open_ports', [])
            
            for port_info in open_ports:
                port = port_info['port']
                protocol = port_info['protocol']
                
                # Enhanced service detection
                service_scan = self.nm.scan(
                    hosts=target,
                    ports=f"{port}/{protocol}",
                    arguments='-sV --version-intensity 9',
                    timeout=Config.SCAN_TIMEOUT
                )
                
                service_data = service_scan['scan'][target][protocol][port]
                
                # SSL/TLS analysis for HTTPS services
                ssl_info = {}
                if service_data['name'] in ['https', 'ssl', 'tls']:
                    ssl_info = await self._analyze_ssl(target, port)
                    
                # HTTP header analysis
                http_headers = {}
                if service_data['name'] in ['http', 'https']:
                    http_headers = await self._analyze_http_headers(target, port)
                    
                result['services'].append({
                    'port': port,
                    'protocol': protocol,
                    'service': service_data['name'],
                    'product': service_data.get('product', ''),
                    'version': service_data.get('version', ''),
                    'extrainfo': service_data.get('extrainfo', ''),
                    'conf': service_data.get('conf', 0),
                    'cpe': service_data.get('cpe', ''),
                    'ssl_info': ssl_info,
                    'http_headers': http_headers
                })
                
            # OS fingerprinting
            try:
                os_scan = self.nm.scan(
                    hosts=target,
                    arguments='-O',
                    timeout=Config.SCAN_TIMEOUT
                )
                result['os_info'] = os_scan['scan'][target].get('osmatch', [])
            except Exception as e:
                logger.warning(f"OS detection failed: {str(e)}")
                
        except Exception as e:
            logger.error(f"Service detection failed: {str(e)}")
            result['error'] = str(e)
            
        return result
        
    async def _analyze_ssl(self, target: str, port: int) -> Dict:
        """Perform comprehensive SSL/TLS analysis"""
        result = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, port)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1,
                        cert
                    )
                    
                    # Certificate details
                    result['certificate'] = {
                        'subject': dict(x509.get_subject().get_components()),
                        'issuer': dict(x509.get_issuer().get_components()),
                        'version': x509.get_version(),
                        'serial_number': x509.get_serial_number(),
                        'not_before': x509.get_notBefore().decode('utf-8'),
                        'not_after': x509.get_notAfter().decode('utf-8'),
                        'signature_algorithm': x509.get_signature_algorithm().decode('utf-8'),
                        'fingerprint': x509.digest('sha1').decode('utf-8')
                    }
                    
                    # Protocol and cipher info
                    result['protocol'] = ssock.version()
                    result['cipher'] = ssock.cipher()
                    
                    # Check for vulnerabilities
                    result['vulnerabilities'] = await self._check_ssl_vulnerabilities(target, port)
                    
        except Exception as e:
            logger.warning(f"SSL analysis failed for {target}:{port}: {str(e)}")
            
        return result
        
    async def _check_ssl_vulnerabilities(self, target: str, port: int) -> List[Dict]:
        """Check for known SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test for Heartbleed
            heartbleed_check = subprocess.run(
                ['openssl', 's_client', '-connect', f"{target}:{port}", '-tlsextdebug'],
                input=b"", capture_output=True, timeout=10
            )
            if b'heartbeat' in heartbleed_check.stderr:
                vulnerabilities.append({
                    'name': 'Heartbleed',
                    'severity': 'critical',
                    'description': 'SSL/TLS Heartbleed vulnerability (CVE-2014-0160)'
                })
                
            # Test for POODLE
            poodle_check = subprocess.run(
                ['openssl', 's_client', '-connect', f"{target}:{port}", '-ssl3'],
                input=b"", capture_output=True, timeout=10
            )
            if b'Protocol  : SSLv3' in poodle_check.stderr:
                vulnerabilities.append({
                    'name': 'POODLE',
                    'severity': 'high',
                    'description': 'SSLv3 POODLE vulnerability (CVE-2014-3566)'
                })
                
        except Exception as e:
            logger.warning(f"SSL vulnerability check failed: {str(e)}")
            
        return vulnerabilities
        
    async def _analyze_http_headers(self, target: str, port: int) -> Dict:
        """Analyze HTTP headers for security information"""
        headers = {}
        
        try:
            url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False) as response:
                    headers = dict(response.headers)
                    
                    # Security header analysis
                    security_headers = {
                        'strict-transport-security': headers.get('Strict-Transport-Security', 'missing'),
                        'content-security-policy': headers.get('Content-Security-Policy', 'missing'),
                        'x-frame-options': headers.get('X-Frame-Options', 'missing'),
                        'x-content-type-options': headers.get('X-Content-Type-Options', 'missing'),
                        'referrer-policy': headers.get('Referrer-Policy', 'missing'),
                        'permissions-policy': headers.get('Permissions-Policy', 'missing')
                    }
                    
                    headers['security_headers'] = security_headers
                    
        except Exception as e:
            logger.warning(f"HTTP header analysis failed: {str(e)}")
            
        return headers
        
    async def _scan_vulnerabilities(self, target: str, service_results: Dict) -> Dict:
        """Perform vulnerability scanning using NSE scripts"""
        result = {
            'vulnerabilities': [],
            'scan_stats': {}
        }
        
        try:
            # Run vulnerability scripts against all services
            vuln_scan = self.nm.scan(
                hosts=target,
                arguments='--script vuln',
                timeout=Config.SCAN_TIMEOUT * 2  # Allow more time for vuln scanning
            )
            
            host_data = vuln_scan['scan'].get(target, {})
            result['scan_stats'] = vuln_scan['nmap']['scanstats']
            
            # Process TCP vulnerabilities
            for port, port_data in host_data.get('tcp', {}).items():
                for script in port_data.get('script', []):
                    if 'vuln' in script.lower() or 'cve' in script.lower():
                        result['vulnerabilities'].append({
                            'port': port,
                            'protocol': 'tcp',
                            'script_id': script,
                            'output': port_data['script'][script],
                            'severity': self._determine_vulnerability_severity(port_data['script'][script])
                        })
                        
            # Process UDP vulnerabilities
            for port, port_data in host_data.get('udp', {}).items():
                for script in port_data.get('script', []):
                    if 'vuln' in script.lower() or 'cve' in script.lower():
                        result['vulnerabilities'].append({
                            'port': port,
                            'protocol': 'udp',
                            'script_id': script,
                            'output': port_data['script'][script],
                            'severity': self._determine_vulnerability_severity(port_data['script'][script])
                        })
                        
            # Additional checks using custom scripts
            custom_vulns = await self._run_custom_vulnerability_checks(target, service_results)
            result['vulnerabilities'].extend(custom_vulns)
            
        except Exception as e:
            logger.error(f"Vulnerability scanning failed: {str(e)}")
            result['error'] = str(e)
            
        return result
        
    async def _run_custom_vulnerability_checks(self, target: str, service_results: Dict) -> List[Dict]:
        """Run additional custom vulnerability checks"""
        vulnerabilities = []
        
        try:
            # Check for common web vulnerabilities
            for service in service_results.get('services', []):
                if service['service'] in ['http', 'https']:
                    # Check for directory traversal
                    traversal_check = await self._check_directory_traversal(
                        target, service['port'])
                    if traversal_check:
                        vulnerabilities.append(traversal_check)
                        
                    # Check for XSS vulnerability
                    xss_check = await self._check_xss_vulnerability(
                        target, service['port'])
                    if xss_check:
                        vulnerabilities.append(xss_check)
                        
        except Exception as e:
            logger.warning(f"Custom vulnerability checks failed: {str(e)}")
            
        return vulnerabilities
        
    async def _check_directory_traversal(self, target: str, port: int) -> Optional[Dict]:
        """Check for directory traversal vulnerability"""
        try:
            url = f"http://{target}:{port}/../../../../etc/passwd" if port != 443 else f"https://{target}/../../../../etc/passwd"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False) as response:
                    if 'root:' in await response.text():
                        return {
                            'port': port,
                            'protocol': 'tcp',
                            'script_id': 'CUSTOM_DIRTRAVERSAL',
                            'output': 'Directory traversal vulnerability found',
                            'severity': 'high'
                        }
        except Exception:
            pass
            
        return None
        
    async def _check_xss_vulnerability(self, target: str, port: int) -> Optional[Dict]:
        """Check for reflected XSS vulnerability"""
        try:
            test_payload = "<script>alert('XSS')</script>"
            url = f"http://{target}:{port}/search?q={test_payload}" if port != 443 else f"https://{target}/search?q={test_payload}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False) as response:
                    if test_payload in await response.text():
                        return {
                            'port': port,
                            'protocol': 'tcp',
                            'script_id': 'CUSTOM_XSS',
                            'output': 'Reflected XSS vulnerability found',
                            'severity': 'medium'
                        }
        except Exception:
            pass
            
        return None
        
    def _determine_vulnerability_severity(self, output: str) -> str:
        """Determine vulnerability severity based on output"""
        output_lower = output.lower()
        
        if 'critical' in output_lower or 'rce' in output_lower or 'remote code execution' in output_lower:
            return 'critical'
        elif 'high' in output_lower or 'sqli' in output_lower or 'sql injection' in output_lower:
            return 'high'
        elif 'medium' in output_lower or 'xss' in output_lower or 'cross-site scripting' in output_lower:
            return 'medium'
        elif 'low' in output_lower or 'info' in output_lower or 'information disclosure' in output_lower:
            return 'low'
        else:
            return 'unknown'
            
    async def _analyze_network(self, target: str, scan_results: Dict) -> Dict:
        """Perform network analysis and visualization"""
        result = {
            'network_map': {},
            'attack_paths': [],
            'risk_assessment': {}
        }
        
        try:
            # Build network topology
            network_graph = nx.Graph()
            network_graph.add_node(target, type='target')
            
            # Add services as nodes
            for service in scan_results.get('services', []):
                service_node = f"{target}:{service['port']}"
                network_graph.add_node(service_node, type='service', **service)
                network_graph.add_edge(target, service_node)
                
            # Add vulnerabilities
            for vuln in scan_results.get('vulnerabilities', []):
                vuln_node = f"vuln_{uuid4().hex[:8]}"
                network_graph.add_node(vuln_node, type='vulnerability', **vuln)
                service_node = f"{target}:{vuln['port']}"
                network_graph.add_edge(service_node, vuln_node)
                
            # Generate network map data
            result['network_map'] = nx.node_link_data(network_graph)
            
            # Identify attack paths
            result['attack_paths'] = self._identify_attack_paths(network_graph)
            
            # Risk assessment
            result['risk_assessment'] = self._assess_risk(scan_results)
            
        except Exception as e:
            logger.error(f"Network analysis failed: {str(e)}")
            result['error'] = str(e)
            
        return result
        
    def _identify_attack_paths(self, graph: nx.Graph) -> List[Dict]:
        """Identify potential attack paths in the network"""
        attack_paths = []
        
        try:
            # Find all critical vulnerabilities
            critical_nodes = [
                n for n, attrs in graph.nodes(data=True)
                if attrs.get('type') == 'vulnerability' and attrs.get('severity') == 'critical'
            ]
            
            # For each critical vulnerability, find paths from target
            for vuln_node in critical_nodes:
                try:
                    path = nx.shortest_path(graph, source=list(graph.nodes())[0], target=vuln_node)
                    attack_paths.append({
                        'vulnerability': graph.nodes[vuln_node],
                        'path': path,
                        'path_length': len(path) - 1
                    })
                except nx.NetworkXNoPath:
                    continue
                    
        except Exception as e:
            logger.warning(f"Attack path identification failed: {str(e)}")
            
        return attack_paths
        
    def _assess_risk(self, scan_results: Dict) -> Dict:
        """Perform comprehensive risk assessment"""
        risk = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0,
            'cvss_scores': [],
            'business_impact': 'low'
        }
        
        try:
            # Count vulnerabilities by severity
            for vuln in scan_results.get('vulnerabilities', []):
                risk[vuln.get('severity', 'unknown')] += 1
                
            # Calculate average CVSS score (simplified)
            if risk['critical'] > 0:
                risk['business_impact'] = 'critical'
            elif risk['high'] > 3:
                risk['business_impact'] = 'high'
            elif risk['medium'] > 5:
                risk['business_impact'] = 'medium'
            else:
                risk['business_impact'] = 'low'
                
        except Exception as e:
            logger.warning(f"Risk assessment failed: {str(e)}")
            
        return risk
        
    async def _generate_reports(self, target: str, scan_data: Dict) -> Dict:
        """Generate comprehensive reports in all formats"""
        report_paths = {}
        
        try:
            # Prepare output directory
            report_dir = Config.OUTPUT_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            report_dir.mkdir(exist_ok=True)
            
            # Generate each report format
            for fmt in Config.REPORT_FORMATS:
                try:
                    if fmt == 'pdf':
                        path = await self._generate_pdf_report(target, scan_data, report_dir)
                        report_paths['pdf'] = str(path)
                    elif fmt == 'html':
                        path = await self._generate_html_report(target, scan_data, report_dir)
                        report_paths['html'] = str(path)
                    elif fmt == 'json':
                        path = await self._generate_json_report(target, scan_data, report_dir)
                        report_paths['json'] = str(path)
                    elif fmt == 'csv':
                        path = await self._generate_csv_report(target, scan_data, report_dir)
                        report_paths['csv'] = str(path)
                    elif fmt == 'xml':
                        path = await self._generate_xml_report(target, scan_data, report_dir)
                        report_paths['xml'] = str(path)
                    elif fmt == 'md':
                        path = await self._generate_markdown_report(target, scan_data, report_dir)
                        report_paths['md'] = str(path)
                    elif fmt == 'svg':
                        path = await self._generate_svg_report(target, scan_data, report_dir)
                        report_paths['svg'] = str(path)
                    elif fmt == 'png':
                        path = await self._generate_png_report(target, scan_data, report_dir)
                        report_paths['png'] = str(path)
                except Exception as e:
                    logger.warning(f"Failed to generate {fmt} report: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            raise
            
        return report_paths
        
    async def _generate_pdf_report(self, target: str, scan_data: Dict, report_dir: Path) -> Path:
        """Generate PDF report from HTML"""
        try:
            # Generate comprehensive HTML first
            html_path = await self._generate_html_report(target, scan_data, report_dir)
        
            # PDF options
            options = {
                'page-size': 'A3',
                'margin-top': '0.5in',
                'margin-right': '0.5in',
                'margin-bottom': '0.5in',
                'margin-left': '0.5in',
                'encoding': "UTF-8",
                'custom-header': [
                    ('Accept-Encoding', 'gzip')
                ],
                'enable-local-file-access': None
            }
        
            pdf_path = report_dir / f"full_report_{target}.pdf"
            pdfkit.from_file(
                str(html_path), 
                str(pdf_path), 
                options=options,
                configuration=pdfkit.configuration(wkhtmltopdf=Config.WKHTMLTOPDF_PATH)
            )
        
            return pdf_path
        except Exception as e:
            logger.error(f"PDF generation failed: {str(e)}")
            raise
            
    async def _generate_html_report(self, target: str, scan_data: Dict, report_dir: Path) -> Path:
        """Generate interactive HTML report with visualizations"""
        try:
            # Load template
            env = Environment(loader=FileSystemLoader(str(Config.TEMPLATE_DIR)))
            template = env.get_template('report_template.html')
            
            # Generate visualizations
            visualizations = await self._generate_report_visualizations(scan_data)
            
            # Render template
            html_content = template.render(
                target=target,
                scan_data=scan_data,
                visualizations=visualizations,
                scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                scan_id=self.scan_id
            )
            
            # Save HTML file
            html_path = report_dir / f"report_{target}.html"
            with open(html_path, 'w') as f:
                f.write(html_content)
                
            return html_path
        except Exception as e:
            logger.error(f"HTML report generation failed: {str(e)}")
            raise
            
    async def _generate_json_report(self, target: str, scan_data: Dict, report_dir: Path) -> Path:
        """Generate JSON report with all scan data"""
        try:
            json_path = report_dir / f"report_{target}.json"
            with open(json_path, 'w') as f:
                json.dump(scan_data, f, indent=2, default=str)
                
            return json_path
        except Exception as e:
            logger.error(f"JSON report generation failed: {str(e)}")
            raise
            
    async def _generate_csv_report(self, target: str, scan_data: Dict, report_dir: Path) -> Path:
        """Generate CSV report with key findings"""
        try:
            csv_path = report_dir / f"report_{target}.csv"
            
            # Prepare CSV data
            csv_data = []
            
            # Add vulnerabilities
            for vuln in scan_data.get('vulnerability_results', {}).get('vulnerabilities', []):
                csv_data.append({
                    'Type': 'Vulnerability',
                    'Port': vuln.get('port', ''),
                    'Protocol': vuln.get('protocol', ''),
                    'Severity': vuln.get('severity', ''),
                    'Description': vuln.get('output', '')
                })
                
            # Add services
            for service in scan_data.get('service_results', {}).get('services', []):
                csv_data.append({
                    'Type': 'Service',
                    'Port': service.get('port', ''),
                    'Protocol': service.get('protocol', ''),
                    'Service': service.get('service', ''),
                    'Version': service.get('version', '')
                })
                
            # Write CSV
            if csv_data:
                with open(csv_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
                    writer.writeheader()
                    writer.writerows(csv_data)
                    
            return csv_path
        except Exception as e:
            logger.error(f"CSV report generation failed: {str(e)}")
            raise
            
    async def _generate_xml_report(self, target: str, scan_data: Dict, report_dir: Path) -> Path:
        """Generate XML report in Nmap-style format"""
        try:
            xml_path = report_dir / f"report_{target}.xml"
            
            # Create XML structure
            root = ET.Element('nmaprun', scanner='VulnerabilityScannerPro', start=str(int(time.time())))
            
            # Add host information
            host = ET.SubElement(root, 'host')
            address = ET.SubElement(host, 'address', addr=target)
            
            # Add ports
            ports = ET.SubElement(host, 'ports')
            for port_info in scan_data.get('port_results', {}).get('open_ports', []):
                port = ET.SubElement(ports, 'port', 
                    portid=str(port_info['port']), 
                    protocol=port_info['protocol'])
                state = ET.SubElement(port, 'state', state=port_info['state'])
                service = ET.SubElement(port, 'service', name=port_info.get('service', ''))
                
            # Add vulnerabilities
            vulns = ET.SubElement(root, 'vulnerabilities')
            for vuln in scan_data.get('vulnerability_results', {}).get('vulnerabilities', []):
                vuln_elem = ET.SubElement(vulns, 'vulnerability',
                    port=str(vuln['port']),
                    protocol=vuln['protocol'],
                    severity=vuln['severity'])
                ET.SubElement(vuln_elem, 'description').text = vuln['output']
                
            # Write XML
            tree = ET.ElementTree(root)
            tree.write(xml_path, encoding='utf-8', xml_declaration=True)
            
            return xml_path
        except Exception as e:
            logger.error(f"XML report generation failed: {str(e)}")
            raise
            
    async def _generate_markdown_report(self, target: str, scan_data: Dict, report_dir: Path) -> Path:
        """Generate Markdown report with findings"""
        try:
            md_path = report_dir / f"report_{target}.md"
            
            # Prepare markdown content
            md_content = f"""
# Vulnerability Scan Report

**Target**: `{target}`  
**Scan ID**: `{self.scan_id}`  
**Scan Time**: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`  

## Summary

- **Open Ports**: {len(scan_data.get('port_results', {}).get('open_ports', []))}
- **Services Found**: {len(scan_data.get('service_results', {}).get('services', []))}
- **Vulnerabilities Found**: {len(scan_data.get('vulnerability_results', {}).get('vulnerabilities', []))}

## Detailed Findings

### Open Ports
"""
            # Add ports
            for port in scan_data.get('port_results', {}).get('open_ports', []):
                md_content += f"- `{port['port']}/{port['protocol']}`: {port.get('service', 'unknown')}\n"
                
            # Add vulnerabilities
            md_content += "\n### Vulnerabilities\n"
            for vuln in scan_data.get('vulnerability_results', {}).get('vulnerabilities', []):
                md_content += f"""
#### {vuln.get('severity', 'Unknown').title()} Severity - Port {vuln['port']}/{vuln['protocol']}
**Description**: {vuln['output']}  
"""
                
            # Write markdown file
            with open(md_path, 'w') as f:
                f.write(md_content)
                
            return md_path
        except Exception as e:
            logger.error(f"Markdown report generation failed: {str(e)}")
            raise
            
    async def _generate_svg_report(self, target: str, scan_data: Dict, report_dir: Path) -> Path:
        """Generate SVG visualization of network map"""
        try:
            svg_path = report_dir / f"network_map_{target}.svg"
            
            # Create network graph visualization
            plt.figure(figsize=(12, 8))
            
            # Generate the graph (simplified example)
            G = nx.Graph()
            G.add_node(target)
            
            for service in scan_data.get('service_results', {}).get('services', []):
                G.add_node(f"{target}:{service['port']}")
                G.add_edge(target, f"{target}:{service['port']}")
                
            pos = nx.spring_layout(G)
            nx.draw(G, pos, with_labels=True, node_size=2000, node_color='lightblue')
            
            plt.savefig(svg_path, format='svg')
            plt.close()
            
            return svg_path
        except Exception as e:
            logger.error(f"SVG report generation failed: {str(e)}")
            raise
            
    async def _generate_png_report(self, target: str, scan_data: Dict, report_dir: Path) -> Path:
        """Generate PNG visualization of vulnerabilities by severity"""
        try:
            png_path = report_dir / f"vulnerabilities_{target}.png"
            
            # Count vulnerabilities by severity
            vuln_counts = defaultdict(int)
            for vuln in scan_data.get('vulnerability_results', {}).get('vulnerabilities', []):
                vuln_counts[vuln.get('severity', 'unknown')] += 1
                
            # Create bar chart
            plt.figure(figsize=(10, 6))
            sns.barplot(
                x=list(vuln_counts.keys()),
                y=list(vuln_counts.values()),
                palette=['red', 'orange', 'yellow', 'green', 'gray']
            )
            plt.title(f"Vulnerabilities by Severity - {target}")
            plt.xlabel("Severity Level")
            plt.ylabel("Count")
            
            plt.savefig(png_path, format='png')
            plt.close()
            
            return png_path
        except Exception as e:
            logger.error(f"PNG report generation failed: {str(e)}")
            raise
            
    async def _generate_report_visualizations(self, scan_data: Dict) -> Dict:
        """Generate data for interactive visualizations in HTML report"""
        visualizations = {}
        
        try:
            # Network map
            network_map_path = await self._generate_svg_report(scan_data.get('target_info', {}).get('target', 'unknown'), scan_data, Path(Config.OUTPUT_DIR))
            visualizations['network_map_image'] = network_map_path.name
            
            # Vulnerability severity distribution
            vuln_counts = defaultdict(int)
            for vuln in scan_data.get('vulnerability_results', {}).get('vulnerabilities', []):
                vuln_counts[vuln.get('severity', 'unknown')] += 1
                
            visualizations['vulnerability_distribution'] = {
                'labels': list(vuln_counts.keys()),
                'values': list(vuln_counts.values()),
                'colors': ['#ff0000', '#ff6600', '#ffcc00', '#33cc33', '#999999']
            }
            
            # Service distribution
            service_counts = defaultdict(int)
            for service in scan_data.get('service_results', {}).get('services', []):
                service_counts[service.get('service', 'unknown')] += 1
                
            visualizations['service_distribution'] = {
                'labels': list(service_counts.keys()),
                'values': list(service_counts.values())
            }
            
            # Network map data
            visualizations['network_map'] = scan_data.get('network_results', {}).get('network_map', {})
            
        except Exception as e:
            logger.warning(f"Visualization data generation failed: {str(e)}")
            
        return visualizations

# Command Line Interface
def main():
    """Command line interface for the scanner"""
    parser = argparse.ArgumentParser(
        description='ULTIMATE VULNERABILITY SCANNER PRO - Enterprise-grade security assessment platform',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument('target', help='Target IP address or hostname to scan')
    parser.add_argument('-p', '--ports', default=Config.DEFAULT_PORTS,
                       help='Ports to scan (comma-separated)')
    parser.add_argument('--script', default='vuln', 
                      help='NSE scripts to use (comma-separated or "all")')
    parser.add_argument('-A', '--aggressive', action='store_true',
                      help='Enable aggressive scan (-A)')
    parser.add_argument('-T', '--timing', type=int, choices=range(0,6), default=3,
                      help='Timing template (0-5)')
    parser.add_argument('--nmap-args', default='',
                      help='Additional nmap arguments')                                     
    parser.add_argument('-i', '--intensity', choices=['stealth', 'normal', 'aggressive', 'comprehensive'],
                       default='normal', help='Scan intensity level')
    parser.add_argument('-o', '--output', help='Output directory for reports',
                       default=str(Config.OUTPUT_DIR))
    parser.add_argument('--shodan', action='store_true', help='Enable Shodan integration')
    parser.add_argument('--censys', action='store_true', help='Enable Censys integration')
    parser.add_argument('--virustotal', action='store_true', help='Enable VirusTotal integration')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    # Validate configuration
    Config.validate()
    
    # Run the scan
    scanner = VulnerabilityScanner()
    
    try:
        # Run async scan
        loop = asyncio.get_event_loop()
        scan_results = loop.run_until_complete(
            scanner.run_scan(args.target, args.ports, args.intensity)
        )
        
        print(f"\n[bold green]Scan completed successfully![/bold green]")
        print(f"Reports saved to: {scan_results.get('reports', {}).get('html', '')}")
        
    except KeyboardInterrupt:
        print("\n[bold red]Scan interrupted by user![/bold red]")
        sys.exit(1)
    except Exception as e:
        print(f"\n[bold red]Scan failed: {str(e)}[/bold red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
