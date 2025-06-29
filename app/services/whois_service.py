import dns.resolver
import requests
import json
from typing import Dict, List, Optional
import os
from dotenv import load_dotenv
import logging
from datetime import datetime
import sys
import pathlib

# Set up logging
LOG_FILE = "logs/server.log"

# Create logs directory if it doesn't exist
log_dir = pathlib.Path(LOG_FILE).parent
log_dir.mkdir(parents=True, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Add debug logging for requests
try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client
http_client.HTTPConnection.debuglevel = 1

requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WhoisService:
    WHOIS_API_KEY = os.getenv('WHOIS_API_KEY')
    WHOIS_API_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={}&domainName={}&outputFormat=json"
    IP2LOCATION_API_KEY = os.getenv('IP2LOCATION_API_KEY')
    IP2LOCATION_API_URL = "https://api.ip2location.io/?key={}&ip={}&package=WS10"
    
    # List of domains that typically have restricted WHOIS information
    RESTRICTED_DOMAINS = [
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
        'apple.com', 'twitter.com', 'instagram.com', 'linkedin.com',
        'youtube.com', 'netflix.com', 'wikipedia.org'
    ]

    @classmethod
    def initialize(cls):
        """Initialize the service by checking environment variables"""
        try:
            if not cls.WHOIS_API_KEY:
                raise ValueError("WHOIS_API_KEY not found in environment")
            if not cls.IP2LOCATION_API_KEY:
                raise ValueError("IP2LOCATION_API_KEY not found in environment")
            
            logger.info("WHOIS service initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing WHOIS service: {str(e)}")
            raise

    @staticmethod
    def _get_whois_data(domain: str) -> Dict:
        """Get WHOIS data from WhoisXML API"""
        try:
            if not WhoisService.WHOIS_API_KEY:
                raise ValueError("WHOIS_API_KEY not set")
                
            # Format the API URL with proper parameter order
            api_url = WhoisService.WHOIS_API_URL.format(WhoisService.WHOIS_API_KEY, domain)
            logger.info(f"Querying WHOIS API for domain: {domain}")
            logger.info(f"API URL: {api_url}")
            
            # Add headers to help with API calls
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'application/json'
            }
            
            try:
                response = requests.get(api_url, headers=headers)
                logger.info(f"Response status code: {response.status_code}")
                logger.info(f"Response headers: {dict(response.headers)}")
                
                if response.status_code != 200:
                    logger.error(f"WHOIS API returned status code: {response.status_code}")
                    logger.error(f"Response content: {response.text}")
                    response.raise_for_status()
                
                data = response.json()
                logger.info(f"Successfully retrieved WHOIS data for {domain}")
                logger.info(f"WHOIS data keys: {list(data.keys())}")
                logger.info(f"Raw WHOIS response: {json.dumps(data, indent=2)}")
                
                # Get the WhoisRecord from the response
                record = data.get('WhoisRecord', {})
                
                # Process the WHOIS response
                whois_data = {
                    'domain': domain,
                    'creation_date': record.get('createdDateNormalized', None) or record.get('createdDate', None),
                    'expiration_date': record.get('expiresDateNormalized', None) or record.get('expiresDate', None),
                    'registrar': record.get('registrarName', None),
                    'registrant_name': record.get('registrantName', None),
                    'registrant_organization': record.get('registrantOrganization', None),
                    'registrant_country': record.get('registrantCountry', None),
                    'admin_name': record.get('adminName', None),
                    'admin_organization': record.get('adminOrganization', None),
                    'admin_country': record.get('adminCountry', None),
                    'tech_name': record.get('techName', None),
                    'tech_organization': record.get('techOrganization', None),
                    'tech_country': record.get('techCountry', None),
                    'dnssec': record.get('dnssec', 'unsigned'),
                    'name_servers': record.get('nameServers', {}),
                    'mx_records': [],  # WhoisXML does not provide MX records
                    'ipv4_addresses': [],  # Not available directly
                    'ipv6_addresses': [],  # Not available directly
                    'domain_status': record.get('domainStatus', [])
                }
                
                # Handle both formats of name servers
                if isinstance(whois_data['name_servers'], dict):
                    whois_data['name_servers'] = whois_data['name_servers'].get('hostNames', [])
                elif not isinstance(whois_data['name_servers'], list):
                    whois_data['name_servers'] = []
                
                # Handle domain status
                if isinstance(whois_data['domain_status'], str):
                    whois_data['domain_status'] = [whois_data['domain_status']]
                elif isinstance(whois_data['domain_status'], dict):
                    whois_data['domain_status'] = whois_data['domain_status'].get('domainStatus', [])
                elif not isinstance(whois_data['domain_status'], list):
                    whois_data['domain_status'] = []
                
                # Clean up domain status URLs if present
                whois_data['domain_status'] = [
                    status.split()[0]  # Take only the status code, not the URL
                    for status in whois_data['domain_status']
                    if status
                ]
                
                # Handle domain status from raw text
                if 'Domain Status:' in record.get('strippedText', ''):
                    status_lines = record['strippedText'].split('\n')
                    raw_statuses = [
                        line.split(':')[1].strip()
                        for line in status_lines
                        if line.startswith('Domain Status:')
                    ]
                    whois_data['domain_status'].extend([
                        status.split()[0]  # Take only the status code
                        for status in raw_statuses
                        if status
                    ])
                
                # Remove duplicates and sort
                whois_data['domain_status'] = sorted(set(whois_data['domain_status']))
                
                # Add basic validation
                if not any(whois_data.values()):
                    raise ValueError(f"No WHOIS data returned for domain {domain}")
                
                return whois_data
                
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding WHOIS response for {domain}: {str(e)}")
                raise ValueError(f"Failed to decode WHOIS response for domain {domain}")
            except Exception as e:
                logger.error(f"Error getting WHOIS data for {domain}: {str(e)}")
                raise ValueError(f"Failed to get WHOIS data for domain {domain}")
        except ValueError as e:
            logger.error(f"Value error for domain {domain}: {str(e)}")
            raise

    @staticmethod
    def _get_ip_location(ip: str) -> Dict:
        """Get location information for an IP address using IP2Location API"""
        try:
            if not WhoisService.IP2LOCATION_API_KEY:
                raise ValueError("IP2LOCATION_API_KEY not set")
                
            api_url = WhoisService.IP2LOCATION_API_URL.format(WhoisService.IP2LOCATION_API_KEY, ip)
            logger.info(f"Querying IP2Location API for IP: {ip}")
            
            response = requests.get(api_url)
            if response.status_code != 200:
                logger.error(f"IP2Location API returned status code: {response.status_code}")
                response.raise_for_status()
                
            data = response.json()
            logger.info(f"Successfully retrieved location data for IP: {ip}")
            return data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for IP {ip}: {str(e)}")
            raise
        except ValueError as e:
            logger.error(f"Value error for IP {ip}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error for IP {ip}: {str(e)}")
            raise

    @staticmethod
    def get_domain_info(domain: str) -> Dict[str, Optional[str]]:
        try:
            # Initialize the service
            WhoisService.initialize()
            
            # Remove any protocol and www prefix
            domain = domain.replace('http://', '').replace('https://', '').replace('www.', '')
            
            # Initialize empty info dictionary
            info = {
                'domain': domain,
                'name_servers': [],
                'mx_records': [],
                'ipv4_addresses': [],
                'ipv6_addresses': [],
                'domain_status': [],
                'ipv4_locations': [],
                'ipv6_locations': []
            }
            
            # Check if this is a restricted domain
            is_restricted = domain.lower() in [d.lower() for d in WhoisService.RESTRICTED_DOMAINS]
            
            try:
                # Get WHOIS data from API first
                whois_data = WhoisService._get_whois_data(domain)
                
                # Log the raw WHOIS data
                logger.info(f"Raw WHOIS data for {domain}: {json.dumps(whois_data, indent=2)}")
                
                # Extract WHOIS information if available
                if is_restricted:
                    logger.info(f"Domain {domain} is in restricted list; using DNS-only lookup to populate basic information.")
                    # Populate name servers
                    try:
                        ns_records = dns.resolver.resolve(domain, 'NS')
                        info['name_servers'] = [str(ns) for ns in ns_records]
                    except Exception as e:
                        logger.error(f"NS lookup failed for {domain}: {str(e)}")

                    # Populate MX records
                    try:
                        mx_records = dns.resolver.resolve(domain, 'MX')
                        info['mx_records'] = [str(mx.exchange) for mx in mx_records]
                    except Exception as e:
                        logger.error(f"MX lookup failed for {domain}: {str(e)}")

                    # Populate IPv4 addresses and their locations
                    try:
                        a_records = dns.resolver.resolve(domain, 'A')
                        info['ipv4_addresses'] = [str(ip) for ip in a_records]
                        for ip in info['ipv4_addresses']:
                            try:
                                location = WhoisService._get_ip_location(ip)
                                info['ipv4_locations'].append({
                                    'ip': ip,
                                    'country': location.get('country_name'),
                                    'region': location.get('region_name'),
                                    'city': location.get('city_name'),
                                    'latitude': location.get('latitude'),
                                    'longitude': location.get('longitude')
                                })
                            except Exception as e:
                                logger.error(f"Failed to get location for IPv4 {ip}: {str(e)}")
                    except Exception as e:
                        logger.error(f"A record lookup failed for {domain}: {str(e)}")

                    # Populate IPv6 addresses and their locations
                    try:
                        aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                        info['ipv6_addresses'] = [str(ip) for ip in aaaa_records]
                        for ip in info['ipv6_addresses']:
                            try:
                                location = WhoisService._get_ip_location(ip)
                                info['ipv6_locations'].append({
                                    'ip': ip,
                                    'country': location.get('country_name'),
                                    'region': location.get('region_name'),
                                    'city': location.get('city_name'),
                                    'latitude': location.get('latitude'),
                                    'longitude': location.get('longitude')
                                })
                            except Exception as e:
                                logger.error(f"Failed to get location for IPv6 {ip}: {str(e)}")
                    except Exception as e:
                        logger.error(f"AAAA record lookup failed for {domain}: {str(e)}")

                    # Even though the domain is restricted, use non-sensitive WHOIS data when available
                    if whois_data:
                        info.update({
                            'creation_date': whois_data.get('creation_date', ''),
                            'expiration_date': whois_data.get('expiration_date', ''),
                            'registrar': whois_data.get('registrar', ''),
                            'domain_status': whois_data.get('domain_status', [])
                        })
                        # Calculate domain age
                        if info['creation_date']:
                            try:
                                creation_date = datetime.strptime(info['creation_date'].split()[0], '%Y-%m-%d')
                                age = datetime.now() - creation_date
                                info['domain_age'] = f"{age.days} days"
                            except Exception as e:
                                logger.error(f"Error calculating domain age: {str(e)}")
                if whois_data and not is_restricted:
                    info.update({
                        'creation_date': whois_data.get('creation_date', None),
                        'expiration_date': whois_data.get('expiration_date', None),
                        'registrar': whois_data.get('registrar', None),
                        'registrant_name': whois_data.get('registrant_name', None),
                        'registrant_organization': whois_data.get('registrant_organization', None),
                        'registrant_country': whois_data.get('registrant_country', None),
                        'admin_name': whois_data.get('admin_name', None),
                        'admin_organization': whois_data.get('admin_organization', None),
                        'admin_country': whois_data.get('admin_country', None),
                        'tech_name': whois_data.get('tech_name', None),
                        'tech_organization': whois_data.get('tech_organization', None),
                        'tech_country': whois_data.get('tech_country', None),
                        'dnssec': whois_data.get('dnssec', None),
                        'name_servers': whois_data.get('name_servers', []),
                        'mx_records': whois_data.get('mx_records', []),
                        'ipv4_addresses': whois_data.get('ipv4_addresses', []),
                        'domain_age': None
                    })
                    # Calculate domain age
                    if info['creation_date']:
                        try:
                            creation_date = datetime.strptime(info['creation_date'].split()[0], '%Y-%m-%d')
                            age = datetime.now() - creation_date
                            info['domain_age'] = f"{age.days} days"
                        except Exception as e:
                            logger.error(f"Error calculating domain age: {str(e)}")

                
                try:
                    # Get MX records from DNS
                    mx_records = dns.resolver.resolve(domain, 'MX')
                    info['mx_records'] = [str(mx.exchange) for mx in mx_records]
                except Exception as e:
                    logger.error(f"MX lookup failed for {domain}: {str(e)}")
                
                try:
                    # Get IPv4 addresses from DNS
                    a_records = dns.resolver.resolve(domain, 'A')
                    info['ipv4_addresses'] = [str(ip) for ip in a_records]
                    
                    # Get location info for IPv4 addresses
                    for ip in info['ipv4_addresses']:
                        try:
                            location = WhoisService._get_ip_location(ip)
                            info['ipv4_locations'].append({
                                'ip': ip,
                                'country': location.get('country_name'),
                                'region': location.get('region_name'),
                                'city': location.get('city_name'),
                                'latitude': location.get('latitude'),
                                'longitude': location.get('longitude')
                            })
                        except Exception as e:
                            logger.error(f"Failed to get location for IPv4 {ip}: {str(e)}")
                except Exception as e:
                    logger.error(f"A record lookup failed for {domain}: {str(e)}")
                
                try:
                    # Get IPv6 addresses from DNS
                    aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                    info['ipv6_addresses'] = [str(ip) for ip in aaaa_records]
                    
                    # Get location info for IPv6 addresses
                    for ip in info['ipv6_addresses']:
                        try:
                            location = WhoisService._get_ip_location(ip)
                            info['ipv6_locations'].append({
                                'ip': ip,
                                'country': location.get('country_name'),
                                'region': location.get('region_name'),
                                'city': location.get('city_name'),
                                'latitude': location.get('latitude'),
                                'longitude': location.get('longitude')
                            })
                        except Exception as e:
                            logger.error(f"Failed to get location for IPv6 {ip}: {str(e)}")
                except Exception as e:
                    logger.error(f"AAAA record lookup failed for {domain}: {str(e)}")
                    try:
                        creation_date = datetime.strptime(info['creation_date'], '%Y-%m-%d')
                        age = datetime.now() - creation_date
                        info['domain_age'] = str(age.days) + ' days'
                    except Exception as e:
                        logger.error(f"Error calculating domain age: {str(e)}")
                
                # If WHOIS returned nameservers, use those instead of DNS lookup
                if whois_data.get('name_servers'):
                    info['name_servers'] = whois_data['name_servers']
                else:
                    try:
                        # Get nameservers from DNS
                        ns_records = dns.resolver.resolve(domain, 'NS')
                        info['name_servers'] = [str(ns) for ns in ns_records]
                    except Exception as e:
                        logger.error(f"NS lookup failed for {domain}: {str(e)}")
                
                # If WHOIS returned MX records, use those instead of DNS lookup
                if whois_data.get('mx_records'):
                    info['mx_records'] = whois_data['mx_records']
                else:
                    try:
                        # Get MX records from DNS
                        mx_records = dns.resolver.resolve(domain, 'MX')
                        info['mx_records'] = [str(mx.exchange) for mx in mx_records]
                    except Exception as e:
                        logger.error(f"MX lookup failed for {domain}: {str(e)}")
                
                # If WHOIS returned IP addresses, use those instead of DNS lookup
                if whois_data.get('ipv4_addresses'):
                    info['ipv4_addresses'] = whois_data['ipv4_addresses']
                else:
                    try:
                        # Get IPv4 addresses from DNS
                        a_records = dns.resolver.resolve(domain, 'A')
                        info['ipv4_addresses'] = [str(ip) for ip in a_records]
                        
                        # Get location info for IPv4 addresses
                        for ip in info['ipv4_addresses']:
                            try:
                                location = WhoisService._get_ip_location(ip)
                                info['ipv4_locations'].append({
                                    'ip': ip,
                                    'country': location.get('country_name'),
                                    'region': location.get('region_name'),
                                    'city': location.get('city_name'),
                                    'latitude': location.get('latitude'),
                                    'longitude': location.get('longitude')
                                })
                            except Exception as e:
                                logger.error(f"Failed to get location for IPv4 {ip}: {str(e)}")
                    except Exception as e:
                        logger.error(f"A record lookup failed for {domain}: {str(e)}")
                
                # Get IPv6 addresses from DNS
                try:
                    aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                    info['ipv6_addresses'] = [str(ip) for ip in aaaa_records]
                    
                    # Get location info for IPv6 addresses
                    for ip in info['ipv6_addresses']:
                        try:
                            location = WhoisService._get_ip_location(ip)
                            info['ipv6_locations'].append({
                                'ip': ip,
                                'country': location.get('country_name'),
                                'region': location.get('region_name'),
                                'city': location.get('city_name'),
                                'latitude': location.get('latitude'),
                                'longitude': location.get('longitude')
                            })
                        except Exception as e:
                            logger.error(f"Failed to get location for IPv6 {ip}: {str(e)}")
                except Exception as e:
                    logger.error(f"AAAA record lookup failed for {domain}: {str(e)}")
            
            except Exception as e:
                logger.error(f"WHOIS processing failed for {domain}: {str(e)}")
            return info
        except Exception as e:
            logger.error(f"Error in get_domain_info for {domain}: {str(e)}")
            raise Exception(f"Error fetching domain information: {str(e)}")
