import json
import logging
import socket
import sys
import time
import signal
import queue
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple
from functools import lru_cache
from threading import Lock
import pickle
import os
import builtins
import argparse
import requests
from ipwhois import IPWhois
from ping3 import ping
from tqdm import tqdm
import geoip2.database
import geoip2.errors
import ipaddress
import subprocess
import re
import matplotlib.pyplot as plt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ANSI color codes for terminal output
class Colors:
    def __init__(self, use_color=True):
        self.HEADER = '\033[95m' if use_color else ''
        self.BLUE = '\033[94m' if use_color else ''
        self.GREEN = '\033[92m' if use_color else ''
        self.END = '\033[0m' if use_color else ''
        self.border_char = '═' if use_color else '-'
        self.v_border_char = '║' if use_color else '|'
        self.sep_char = '─' if use_color else '-'

# Configure logging
logging.getLogger('urllib3').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
file_handler = logging.FileHandler(os.path.join(BASE_DIR, 'nkn_crawler.log'))
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
logger.handlers = [console_handler, file_handler]
logger.setLevel(logging.DEBUG)

# US state name to abbreviation mapping
US_STATE_ABBREVIATIONS = {
    'Alabama': 'AL', 'AL': 'AL', 'Alaska': 'AK', 'AK': 'AK', 'Arizona': 'AZ', 'AZ': 'AZ',
    'Arkansas': 'AR', 'AR': 'AR', 'California': 'CA', 'CA': 'CA', 'Colorado': 'CO', 'CO': 'CO',
    'Connecticut': 'CT', 'CT': 'CT', 'Delaware': 'DE', 'DE': 'DE', 'Florida': 'FL', 'FL': 'FL',
    'Georgia': 'GA', 'GA': 'GA', 'Hawaii': 'HI', 'HI': 'HI', 'Idaho': 'ID', 'ID': 'ID',
    'Illinois': 'IL', 'IL': 'IL', 'Indiana': 'IN', 'IN': 'IN', 'Iowa': 'IA', 'IA': 'IA',
    'Kansas': 'KS', 'KS': 'KS', 'Kentucky': 'KY', 'KY': 'KY', 'Louisiana': 'LA', 'LA': 'LA',
    'Maine': 'ME', 'ME': 'ME', 'Maryland': 'MD', 'MD': 'MD', 'Massachusetts': 'MA', 'MA': 'MA',
    'Michigan': 'MI', 'MI': 'MI', 'Minnesota': 'MN', 'MN': 'MN', 'Mississippi': 'MS', 'MS': 'MS',
    'Missouri': 'MO', 'MO': 'MO', 'Montana': 'MT', 'MT': 'MT', 'Nebraska': 'NE', 'NE': 'NE',
    'Nevada': 'NV', 'NV': 'NV', 'New Hampshire': 'NH', 'NH': 'NH', 'New Jersey': 'NJ', 'NJ': 'NJ',
    'New Mexico': 'NM', 'NM': 'NM', 'New York': 'NY', 'NY': 'NY', 'North Carolina': 'NC', 'NC': 'NC',
    'North Dakota': 'ND', 'ND': 'ND', 'Ohio': 'OH', 'OH': 'OH', 'Oklahoma': 'OK', 'OK': 'OK',
    'Oregon': 'OR', 'OR': 'OR', 'Pennsylvania': 'PA', 'PA': 'PA', 'Rhode Island': 'RI', 'RI': 'RI',
    'South Carolina': 'SC', 'SC': 'SC', 'South Dakota': 'SD', 'SD': 'SD', 'Tennessee': 'TN', 'TN': 'TN',
    'Texas': 'TX', 'TX': 'TX', 'Utah': 'UT', 'UT': 'UT', 'Vermont': 'VT', 'VT': 'VT',
    'Virginia': 'VA', 'VA': 'VA', 'Washington': 'WA', 'WA': 'WA', 'West Virginia': 'WV', 'WV': 'WV',
    'Wisconsin': 'WI', 'WI': 'WI', 'Wyoming': 'WY', 'WY': 'WY'
}

# Known provider ASNs
RACKSPACE_ASNS = {'19994', '33070', '15395', '45187', '63025'}
M247_ASNS = {'9009'}
LINODE_ASNS = {'63949', '3549'}
WESTIN_ASNS = {'29802', '6939', '3257'}
DIGITALOCEAN_ASN = {'14061'}

class NKNCrawler:
    def __init__(self, target_neighbors: int = 5000, use_tcp_ping: bool = True, use_color: bool = True, debug_geo: bool = False, clear_cache: bool = False):
        self.colors = Colors(use_color)
        self.visited_nodes = set()
        self.neighbors_data = []
        self.target_neighbors = target_neighbors
        self.request_timeout = 15
        self.max_depth = 6
        self.running = True
        self.start_time = time.time()
        self.invalid_rtt_count = 0
        self.whois_cache = {}
        self.geo_cache = {}
        self.dns_cache = {}
        self.whois_local_cache = {}
        self.failed_whois_cache = {}
        self.geo_success = 0
        self.geo_failed = 0
        self.geo_lock = Lock()
        self.use_tcp_ping = use_tcp_ping
        self.max_workers = 20
        self.geo_queue = queue.Queue()
        self.debug_geo = debug_geo
        self.clear_cache = clear_cache
        self.high_loss_nodes = []
        self.geo_reader_city = geoip2.database.Reader(os.path.join(BASE_DIR, 'geoip', 'GeoLite2-City.mmdb'))
        self.geo_reader_asn = geoip2.database.Reader(os.path.join(BASE_DIR, 'geoip', 'GeoLite2-ASN.mmdb'))
        self.ipinfo_token = os.getenv('IPINFO_TOKEN')
        if not clear_cache:
            try:
                with builtins.open(os.path.join(BASE_DIR, 'geo_cache.pkl'), 'rb') as f:
                    self.geo_cache = pickle.load(f)
                with builtins.open(os.path.join(BASE_DIR, 'whois_cache.pkl'), 'rb') as f:
                    self.whois_local_cache = pickle.load(f)
                logger.info(f"Loaded geo_cache with {len(self.geo_cache)} entries, whois_cache with {len(self.whois_local_cache)} entries")
            except FileNotFoundError:
                logger.info("No caches found, starting fresh")
        else:
            logger.info("Clearing caches as requested")
        self.apac_countries = {'JP', 'SG', 'HK', 'KR', 'AU', 'TW', 'MY', 'TH', 'ID', 'PH', 'VN'}
        logger.info(f"Initialized crawler: target={target_neighbors}, use_tcp_ping={use_tcp_ping}, use_color={use_color}, debug_geo={debug_geo}, clear_cache={clear_cache}")

    @lru_cache(maxsize=20000)
    def resolve_ip(self, hostname: str) -> str:
        if hostname in self.dns_cache:
            return self.dns_cache[hostname]
        try:
            ip = socket.gethostbyname(hostname)
            self.dns_cache[hostname] = ip
            logger.debug(f"Resolved {hostname} to {ip}")
            return ip
        except (socket.gaierror, socket.timeout) as e:
            logger.warning(f"DNS resolution failed for {hostname}: {str(e)}")
            self.dns_cache[hostname] = None
            return None

    def get_geolocation(self, ip: str) -> str:
        if not ip or ip == "Unresolved":
            return "Unknown"
        if ip in self.geo_cache and self.geo_cache[ip] not in ("US", "Unknown"):
            return self.geo_cache[ip]

        try:
            city_response = self.geo_reader_city.city(ip)
            country = city_response.country.iso_code or "Unknown"
            city = city_response.city.name or ""
            state = city_response.subdivisions.most_specific.iso_code or ""
            if country == "US" and state:
                state_name = US_STATE_ABBREVIATIONS.get(state, state)
            else:
                state_name = state
            location = f"{city}, {state_name}, {country}" if city and state_name else f"{city}, {country}" if city else f"{state_name}, {country}" if state_name else country
            self.geo_cache[ip] = location
            with self.geo_lock:
                self.geo_success += 1
            if self.debug_geo:
                logger.debug(f"GeoLite2 for {ip}: city={city_response.city.name}, state={city_response.subdivisions.most_specific.iso_code}, country={city_response.country.iso_code}, location={location}")
            return location
        except geoip2.errors.AddressNotFoundError:
            logger.warning(f"GeoLite2 lookup failed for {ip}: Address not found")
        except Exception as e:
            logger.warning(f"GeoLite2 lookup failed for {ip}: {str(e)}")

        for attempt in range(3):
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                data = response.json()
                if data['status'] == 'success':
                    country = data['countryCode']
                    city = data.get('city', '')
                    state = data.get('region', '')
                    if country == "US" and state:
                        state_name = US_STATE_ABBREVIATIONS.get(state, state)
                    else:
                        state_name = state
                    location = f"{city}, {state_name}, {country}" if city and state_name else f"{city}, {country}" if city else f"{state_name}, {country}" if state_name else country
                    self.geo_cache[ip] = location
                    with self.geo_lock:
                        self.geo_success += 1
                    if self.debug_geo:
                        logger.debug(f"ip-api for {ip}: city={city}, state={state}, country={country}, location={location}")
                    return location
                else:
                    logger.warning(f"ip-api lookup failed for {ip}: {data.get('message', 'Unknown error')}")
                    if 'rate limit' in data.get('message', '').lower():
                        time.sleep(2 ** attempt)
            except Exception as e:
                logger.warning(f"ip-api lookup failed for {ip} (attempt {attempt+1}): {str(e)}")
                time.sleep(2 ** attempt)

        if self.ipinfo_token:
            for attempt in range(5):
                try:
                    response = requests.get(f"https://ipinfo.io/{ip}/json?token={self.ipinfo_token}", timeout=5)
                    data = response.json()
                    country = data.get('country', 'Unknown')
                    city = data.get('city', '')
                    state = data.get('region', '')
                    if country == "US" and state:
                        state_name = US_STATE_ABBREVIATIONS.get(state, state)
                    else:
                        state_name = state
                    location = f"{city}, {state_name}, {country}" if city and state_name else f"{city}, {country}" if city else f"{state_name}, {country}" if state_name else country
                    self.geo_cache[ip] = location
                    with self.geo_lock:
                        self.geo_success += 1
                    if self.debug_geo:
                        logger.debug(f"ipinfo.io for {ip}: city={city}, state={state}, country={country}, location={location}")
                    return location
                except Exception as e:
                    logger.warning(f"ipinfo.io lookup failed for {ip} (attempt {attempt+1}): {str(e)}")
                    time.sleep(2 ** attempt)

        try:
            asn_response = self.geo_reader_asn.asn(ip)
            asn = str(asn_response.autonomous_system_number)
            whois_location = self._get_whois_location(ip, asn)
            self.geo_cache[ip] = whois_location
            with self.geo_lock:
                if whois_location != "Unknown":
                    self.geo_success += 1
                else:
                    self.geo_failed += 1
            return whois_location
        except geoip2.errors.AddressNotFoundError:
            logger.warning(f"ASN lookup failed for {ip}: Address not found")
        except Exception as e:
            logger.warning(f"ASN lookup failed for {ip}: {str(e)}")

        self.geo_cache[ip] = "Unknown"
        with self.geo_lock:
            self.geo_failed += 1
        return "Unknown"

    def _get_whois_location(self, ip: str, asn: str = None) -> str:
        if ip in self.geo_cache and self.geo_cache[ip] not in ("US", "Unknown"):
            return self.geo_cache[ip]

        hardcoded_ips = {
            "172.99.114.38": "San Antonio, TX, US",
            "23.186.104.155": "San Antonio, TX, US",
            "104.130.31.57": "San Antonio, TX, US",
            "209.61.160.22": "San Antonio, TX, US",
            "108.171.193.169": "Unknown"
        }
        if ip in hardcoded_ips:
            location = hardcoded_ips[ip]
            self.geo_cache[ip] = location
            with self.geo_lock:
                self.geo_success += 1
            if self.debug_geo:
                logger.debug(f"Hardcoded location for {ip}: {location}")
            return location

        if ip in self.whois_local_cache and self.whois_local_cache[ip] not in ("US", "Unknown"):
            return self.whois_local_cache[ip]

        if ip in self.failed_whois_cache:
            return self.failed_whois_cache[ip]

        if self.geo_cache.get(ip) in ("US", "Unknown"):
            del self.geo_cache[ip]
            if self.debug_geo:
                logger.debug(f"Cleared stale geo cache for {ip} (ASN {asn})")
        if self.whois_local_cache.get(ip) in ("US", "Unknown"):
            del self.whois_local_cache[ip]
            if self.debug_geo:
                logger.debug(f"Cleared stale whois cache for {ip} (ASN {asn})")

        whois_servers = ['whois.arin.net', 'whois.radb.net', 'whois.ripe.net', 'whois.iana.org']
        if asn in RACKSPACE_ASNS:
            whois_servers = ['whois.arin.net', 'whois.radb.net']
        elif asn in M247_ASNS:
            whois_servers = ['whois.ripe.net', 'whois.radb.net']
        elif asn in LINODE_ASNS:
            whois_servers = ['whois.arin.net', 'whois.radb.net']
        elif ip:
            try:
                city_response = self.geo_reader_city.city(ip)
                if city_response.country.iso_code == "US":
                    whois_servers = ['whois.arin.net', 'whois.radb.net']
            except geoip2.errors.AddressNotFoundError:
                pass

        for server in whois_servers:
            try:
                cmd = ['whois', '-h', server, ip]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                whois_output = result.stdout
                if self.debug_geo:
                    logger.debug(f"WHOIS ({server}) raw response for {ip}: {whois_output[:1000]}...")

                city = ''
                state = ''
                country = 'Unknown'
                address_lines = []
                postal_code = ''

                for line in whois_output.splitlines():
                    line = line.strip()
                    if line.startswith(('City:', 'city:', 'Org-Tech-City:', 'Org-Abuse-City:', 'Org-NOC-City:')):
                        city = line.split(':', 1)[1].strip()
                    elif line.startswith(('StateProv:', 'state:', 'Org-Tech-State:', 'Org-Abuse-State:', 'Org-NOC-State:')):
                        state = line.split(':', 1)[1].strip()
                    elif line.startswith(('Country:', 'country:')):
                        country = line.split(':', 1)[1].strip()
                    elif line.startswith(('PostalCode:', 'postal-code:', 'Org-Tech-Postal:', 'Org-Abuse-Postal:', 'Org-NOC-Postal:')):
                        postal_code = line.split(':', 1)[1].strip()
                    elif line.startswith(('Org-Address:', 'Address:', 'address:', 'Org-Tech-Address:', 'Org-Abuse-Address:', 'Org-NOC-Address:')):
                        address_lines.append(line.split(':', 1)[1].strip())

                if not city and not state and address_lines:
                    for addr in address_lines:
                        parts = [p.strip() for p in addr.split(',')]
                        if len(parts) >= 2:
                            city_candidate = parts[0]
                            state_candidate = parts[1]
                            if re.match(r'^[A-Z]{2}$', state_candidate) or state_candidate in US_STATE_ABBREVIATIONS:
                                city = city_candidate
                                state = state_candidate
                                break
                            elif len(parts) >= 3 and (parts[2] in US_STATE_ABBREVIATIONS or re.match(r'^[A-Z]{2}$', parts[2])):
                                city = parts[0]
                                state = parts[2]
                                break
                    addr_match = re.search(r'(.+?),\s*([A-Z]{2})\b', addr)
                    if addr_match:
                        city = addr_match.group(1).strip()
                        state = addr_match.group(2)
                        break

                if not city and postal_code and country == 'US':
                    postal_match = re.match(r'^(\d{5})', postal_code)
                    if postal_match:
                        postal_prefix = postal_match.group(1)
                        if postal_prefix.startswith('782'):
                            city = 'San Antonio'
                            state = 'TX'
                        elif postal_prefix.startswith('606'):
                            city = 'Chicago'
                            state = 'IL'
                        elif postal_prefix.startswith('201'):
                            city = 'Ashburn'
                            state = 'VA'

                if country == "US" and state:
                    state_name = US_STATE_ABBREVIATIONS.get(state.upper(), state)
                else:
                    state_name = state

                location = f"{city}, {state_name}, {country}" if city and state_name else f"{city}, {country}" if city else f"{state_name}, {country}" if state_name else country

                if self.debug_geo:
                    logger.debug(f"WHOIS ({server}) for {ip}: city={city}, state={state_name}, country={country}, postal={postal_code}, address={address_lines}, location={location}")

                if location in ("US", "Unknown"):
                    logger.warning(f"WHOIS ({server}) for {ip} returned vague location: {location}")
                    self.failed_whois_cache[ip] = "Unknown"
                    continue

                self.geo_cache[ip] = location
                self.whois_local_cache[ip] = location
                with self.geo_lock:
                    self.geo_success += 1
                return location
            except subprocess.TimeoutExpired:
                logger.warning(f"WHOIS ({server}) timed out for {ip}")
                self.failed_whois_cache[ip] = "Unknown"
            except Exception as e:
                logger.warning(f"WHOIS ({server}) failed for {ip}: {str(e)}")
                self.failed_whois_cache[ip] = "Unknown"

        if ip in self.failed_whois_cache:
            self.geo_cache[ip] = "Unknown"
            self.whois_local_cache[ip] = "Unknown"
            with self.geo_lock:
                self.geo_failed += 1
            return "Unknown"

    def _get_whois_provider(self, addr: str) -> Tuple[str, bool, str]:
        ip = addr.replace('tcp://', '').split(':')[0]
        resolved_ip = self.resolve_ip(ip)
        if not resolved_ip:
            return "Unknown", False, "N/A"
        if resolved_ip in self.whois_cache:
            return self.whois_cache[resolved_ip]
        try:
            asn_response = self.geo_reader_asn.asn(resolved_ip)
            provider = asn_response.autonomous_system_organization or "Unknown"
            asn = str(asn_response.autonomous_system_number) or "N/A"
            self.whois_cache[resolved_ip] = (provider, True, asn)
        except geoip2.errors.AddressNotFoundError:
            logger.warning(f"ASN lookup failed for {ip}: Address not found")
        except Exception as e:
            logger.warning(f"ASN lookup failed for {ip}: {str(e)}")
            try:
                whois = IPWhois(resolved_ip)
                result = whois.lookup_rdap()
                provider = result.get('network', {}).get('name', 'Unknown')
                asn = result.get('asn', 'N/A')
                if provider.lower() == "unknown":
                    provider = result.get('asn_description', 'Unknown')
                self.whois_cache[resolved_ip] = (provider, True, asn)
            except Exception as e:
                logger.warning(f"WHOIS lookup failed for {ip}: {str(e)}")
                self.whois_cache[resolved_ip] = ("Unknown", False, "N/A")
        return self.whois_cache[resolved_ip]

    def is_apac_node(self, ip: str) -> bool:
        location = self.get_geolocation(ip)
        if location in ("Unknown", "Private IP", "Invalid IP"):
            logger.debug(f"Not APAC: {ip} -> {location}")
            return False
        country_code = location.split(',')[-1].strip()
        is_apac = country_code in self.apac_countries
        logger.debug(f"APAC check: {ip} -> {location}, country={country_code}, is_apac={is_apac}")
        return is_apac

    def is_preferred_node(self, ip: str) -> bool:
        location = self.get_geolocation(ip)
        if location in ("Unknown", "Private IP", "Invalid IP"):
            return False
        region = location.split(',')[-1].strip()
        if ',' in location:
            state = location.split(',')[1].strip() if len(location.split(',')) > 1 else ''
            return state in ('WA', 'OR', 'CA', 'NV', 'AZ') or region in ('US', 'CA')
        return region in ('US', 'CA')

    def crawl_node(self, node_url: str, node_id: str, depth: int = 0):
        if not self.running or depth > self.max_depth or len(self.neighbors_data) >= self.target_neighbors:
            logger.debug(f"Stopping crawl: running={self.running}, depth={depth}, neighbors={len(self.neighbors_data)}/{self.target_neighbors}")
            return
        if node_url in self.visited_nodes:
            logger.debug(f"Skipping visited node: {node_url}")
            return
        self.visited_nodes.add(node_url)
        logger.info(f"Crawling node: {node_url}, depth={depth}")

        payload = {
            "jsonrpc": "2.0",
            "method": "getneighbor",
            "params": {"id": node_id},
            "id": 1
        }
        headers = {'Content-Type': 'application/json'}

        initial_neighbors = len(self.neighbors_data)
        try:
            logger.debug(f"Sending request to {node_url}")
            response = requests.post(node_url, json=payload, headers=headers, timeout=self.request_timeout)
            response.raise_for_status()
            try:
                data = response.json()
                logger.debug(f"Received response: {json.dumps(data, indent=2)}")
            except ValueError as e:
                logger.error(f"Invalid JSON response from {node_url}: {response.text}")
                return

            if 'result' not in data:
                logger.warning(f"No 'result' in response from {node_url}: {json.dumps(data, indent=2)}")
                return
            neighbors = data['result'] if isinstance(data['result'], list) else data['result'].get('neighbors', [])
            if not neighbors:
                logger.info(f"Empty neighbor list from {node_url}")
                return

            logger.debug(f"Found {len(neighbors)} neighbors")
            for neighbor in neighbors:
                if len(self.neighbors_data) >= self.target_neighbors:
                    logger.debug(f"Reached target neighbors: {self.target_neighbors}")
                    break
                raw_addr = neighbor.get('addr')
                if not raw_addr or '://' not in raw_addr or not raw_addr.startswith('tcp://'):
                    logger.warning(f"Invalid address format: {raw_addr}")
                    continue
                neighbor_addr = raw_addr
                neighbor_port = neighbor.get('jsonRpcPort', 30003)
                neighbor_id = neighbor.get('id')
                if not neighbor_id:
                    logger.warning(f"Missing 'id' for {neighbor_addr}")
                    continue
                if not (0 < neighbor_port < 65536):
                    logger.warning(f"Invalid port {neighbor_port} for {neighbor_addr}")
                    continue
                next_node_ip = neighbor['addr'].replace('tcp://', '').split(':')[0]
                resolved_ip = self.resolve_ip(next_node_ip)
                if neighbor_addr not in [n['addr'] for n in self.neighbors_data]:
                    self.neighbors_data.append({
                        "addr": neighbor_addr,
                        "port": neighbor_port,
                        "id": neighbor_id,
                        "ping_rtt": None,
                        "ping_variance": None,
                        "ping_loss": None,
                        "resolved_ip": resolved_ip
                    })
                    logger.debug(f"Added neighbor: {neighbor_addr}:{neighbor_port} with id {neighbor_id}")
                next_node_port = neighbor.get('jsonRpcPort', 30003)
                next_node_url = f"http://{next_node_ip}:{next_node_port}"
                next_node_id = neighbor.get('id')
                if not next_node_id:
                    logger.warning(f"Missing 'id' in neighbor data for {next_node_url}")
                    continue
                self.geo_queue.put((next_node_url, next_node_id, depth + 1))
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed for {node_url}: {str(e)}")
            return

        added_neighbors = len(self.neighbors_data) - initial_neighbors
        logger.info(f"Added {added_neighbors} neighbors from {node_url}")

    def crawl_nodes_concurrently(self):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            while not self.geo_queue.empty() and self.running and len(self.neighbors_data) < self.target_neighbors:
                node_url, node_id, depth = self.geo_queue.get()
                futures.append(executor.submit(self.crawl_node, node_url, node_id, depth))
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.warning(f"Crawl task failed: {str(e)}")

    def perform_ping_tests(self):
        max_neighbors_to_test = 3000
        if not self.neighbors_data:
            logger.warning("No neighbors to ping. Crawling may have failed.")
            return

        logger.info("Prioritizing APAC nodes for ping tests...")
        apac_neighbors = []
        other_neighbors = []
        for neighbor in self.neighbors_data:
            resolved_ip = neighbor.get('resolved_ip')
            if resolved_ip and self.is_apac_node(resolved_ip):
                apac_neighbors.append(neighbor)
            else:
                other_neighbors.append(neighbor)
        neighbors_to_test = apac_neighbors + other_neighbors[:max_neighbors_to_test - len(apac_neighbors)]
        neighbors_to_test = neighbors_to_test[:max_neighbors_to_test]
        logger.info(f"Pinging {len(neighbors_to_test)} neighbors ({len(apac_neighbors)} APAC prioritized) with 0.2s delay...")

        def ping_neighbor(neighbor: Dict):
            addr = neighbor['addr'].replace('tcp://', '')
            ip = addr.split(':')[0]
            resolved_ip = neighbor.get('resolved_ip') or self.resolve_ip(ip)
            if not resolved_ip:
                logger.debug(f"Skipping ping for {addr}: No resolved IP")
                neighbor['ping_rtt'] = None
                neighbor['ping_variance'] = None
                neighbor['ping_loss'] = None
                neighbor['resolved_ip'] = None
                return
            neighbor['resolved_ip'] = resolved_ip

            rtts = []
            packets_sent = 5
            packets_received = 0
            if self.use_tcp_ping:
                try:
                    cmd = ['hping3', '-S', '-p', '30001', '-c', str(packets_sent), '--interval', 'u200000', resolved_ip]
                    logger.debug(f"hping3 command executed: {' '.join(cmd)}")
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                    output = result.stdout
                    error = result.stderr
                    if self.debug_geo:
                        logger.debug(f"hping3 output for {resolved_ip}: {output}")
                        if error:
                            logger.debug(f"hping3 stderr for {resolved_ip}: {error}")

                    rtt_lines = [line for line in output.splitlines() if 'rtt=' in line]
                    for line in rtt_lines:
                        rtt_match = re.search(r'rtt=(\d+\.?\d*)\s*ms', line)
                        if rtt_match:
                            try:
                                rtt_value = float(rtt_match.group(1))
                                if rtt_value > 0:
                                    rtts.append(rtt_value)
                                    packets_received += 1
                            except ValueError:
                                logger.debug(f"Invalid RTT value in line: {line}")
                                continue

                    loss_match = re.search(r'(\d+)% packet loss', output)
                    if loss_match:
                        loss = float(loss_match.group(1))
                        packets_received = int(packets_sent * (100 - loss) / 100)
                    else:
                        loss = ((packets_sent - packets_received) / packets_sent) * 100 if packets_sent > 0 else 100.0
                except subprocess.SubprocessError as e:
                    logger.warning(f"hping3 failed for {resolved_ip}: {str(e)}. Falling back to ping3.")
                    if self.debug_geo:
                        logger.debug(f"hping3 exception details: {str(e)}")
                except FileNotFoundError:
                    logger.error(f"hping3 not found for {resolved_ip}. Falling back to ping3.")
                    self.use_tcp_ping = False

            if not rtts and not self.use_tcp_ping:
                try:
                    for _ in range(packets_sent):
                        rtt = ping(resolved_ip, timeout=3, unit='ms')
                        if rtt is not None and rtt > 0:
                            rtts.append(rtt)
                            packets_received += 1
                        time.sleep(0.2)
                    loss = ((packets_sent - packets_received) / packets_sent) * 100 if packets_sent > 0 else 100.0
                    if self.debug_geo:
                        logger.debug(f"ping3 for {resolved_ip}: rtts={rtts}, loss={loss}%, packets_received={packets_received}/{packets_sent}")
                except Exception as e:
                    logger.warning(f"ping3 failed for {resolved_ip}: {str(e)}")
                    loss = 100.0
                    packets_received = 0

            if not rtts:
                logger.debug(f"No valid RTTs for {resolved_ip}: marking as unreachable")
                neighbor['ping_rtt'] = None
                neighbor['ping_variance'] = None
                neighbor['ping_loss'] = 100.0
                self.high_loss_nodes.append(addr)
                return

            avg_rtt = sum(rtts) / len(rtts)
            variance = sum((x - avg_rtt) ** 2 for x in rtts) / len(rtts) if len(rtts) > 1 else 0
            loss = ((packets_sent - packets_received) / packets_sent) * 100 if packets_sent > 0 else 100.0
            if loss > 50:
                self.high_loss_nodes.append(addr)
            if avg_rtt < 0.1:
                logger.debug(f"Invalid RTT {avg_rtt}ms for {resolved_ip}: too low")
                self.invalid_rtt_count += 1
                neighbor['ping_rtt'] = None
                neighbor['ping_variance'] = None
                neighbor['ping_loss'] = None
            else:
                neighbor['ping_rtt'] = avg_rtt
                neighbor['ping_variance'] = variance
                neighbor['ping_loss'] = loss
                logger.debug(f"Ping results for {resolved_ip}: rtt={avg_rtt:.1f}ms, variance={variance:.1f}, loss={loss}%")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(ping_neighbor, neighbor) for neighbor in neighbors_to_test]
            for future in tqdm(as_completed(futures), total=len(futures), desc="Pinging neighbors", unit="neighbor"):
                try:
                    future.result()
                except Exception as e:
                    logger.warning(f"Ping task failed: {str(e)}")

    def get_top_neighbors_by_latency(self, top_n: int = 50) -> List[Dict]:
        valid_neighbors = [n for n in self.neighbors_data if n["addr"] and n["port"] and n["id"]]
        max_score_neighbors = min(1000, len(valid_neighbors))
        logger.info(f"Calculating scores for {max_score_neighbors} of {len(valid_neighbors)} valid neighbors...")
        if not valid_neighbors:
            logger.error("No valid neighbors for scoring. Crawling phase may have failed.")
            return []
        scored_neighbors = valid_neighbors[:max_score_neighbors]

        logger.info("Resolving IPs in parallel...")
        ip_mappings = {}
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(self.resolve_ip, neighbor['addr'].replace('tcp://', '').split(':')[0]): neighbor
                for neighbor in scored_neighbors
            }
            for future in tqdm(as_completed(futures), total=len(futures), desc="Resolving IPs", unit="IP"):
                neighbor = futures[future]
                try:
                    ip_mappings[neighbor['addr']] = future.result(timeout=5)
                except Exception as e:
                    logger.warning(f"DNS resolution error for {neighbor['addr']}: {str(e)}")
                    ip_mappings[neighbor['addr']] = None

        logger.info(f"Scoring {len(scored_neighbors)} neighbors...")
        apac_neighbors = []
        preferred_neighbors = []
        other_neighbors = []
        whois_results = {}
        batch_size = 20

        def process_neighbor(neighbor):
            addr = neighbor['addr']
            resolved_ip = ip_mappings.get(addr) or neighbor.get('resolved_ip')
            if not resolved_ip:
                return neighbor, float('inf'), False, False, ("Unknown", False, "N/A")
            is_apac = self.is_apac_node(resolved_ip)
            is_preferred = self.is_preferred_node(resolved_ip)
            base_score = (neighbor["ping_rtt"] or float('inf')) + (neighbor["ping_variance"] or 0)
            location = self.get_geolocation(resolved_ip)
            state = location.split(',')[1].strip() if ',' in location and len(location.split(',')) > 1 else ''
            provider, success, asn = self._get_whois_provider(addr)
            asn_counts = Counter([self._get_whois_provider(n['addr'])[2] for n in scored_neighbors])
            asn_penalty = 1.0 + (asn_counts[asn] / len(scored_neighbors))
            score = base_score * (
                0.4 if is_apac else  # Lower multiplier for APAC nodes
                0.65 if asn in WESTIN_ASNS else
                0.7 if state == 'WA' else
                0.75 if state in ('OR', 'CA', 'NV', 'AZ') else
                1.0
            ) * (asn_penalty * 0.7)
            if 'DIGITALOCEAN' in provider.upper() and not is_apac:
                score *= 8  # Increased penalty for non-APAC DigitalOcean nodes
            if is_apac:
                logger.debug(f"APAC node score: {addr} -> score={score}, rtt={neighbor['ping_rtt']}, location={location}")
            return neighbor, score, is_apac, is_preferred, (provider, success, asn)

        with tqdm(total=len(scored_neighbors), desc="Scoring neighbors", unit="neighbor") as pbar:
            for i in range(0, len(scored_neighbors), batch_size):
                batch = scored_neighbors[i:i + batch_size]
                with ThreadPoolExecutor(max_workers=2) as executor:
                    futures = {executor.submit(process_neighbor, neighbor): neighbor for neighbor in batch}
                    for future in as_completed(futures):
                        neighbor = futures[future]
                        try:
                            n, score, is_apac, is_preferred, whois = future.result(timeout=10)
                            n["score"] = score
                            whois_results[n['addr']] = whois
                            if is_apac:
                                apac_neighbors.append(n)
                            elif is_preferred:
                                preferred_neighbors.append(n)
                            else:
                                other_neighbors.append(n)
                            pbar.update(1)
                        except Exception as e:
                            logger.warning(f"Processing failed for {neighbor['addr']}: {str(e)}")
                            neighbor["score"] = float('inf')
                            other_neighbors.append(neighbor)
                            pbar.update(1)

        apac_neighbors.sort(key=lambda x: x["score"])
        preferred_neighbors.sort(key=lambda x: x["score"])
        other_neighbors.sort(key=lambda x: x["score"])

        final_neighbors = []
        apac_quota = sum(1 for n in apac_neighbors if n['ping_rtt'] is not None and n['ping_rtt'] < 250)  # Increased RTT threshold
        apac_quota = min(apac_quota, 45)  # Increased quota

        apac_added = 0
        for neighbor in apac_neighbors:
            if len(final_neighbors) >= top_n:
                break
            final_neighbors.append(neighbor)
            apac_added += 1

        if apac_added < apac_quota:
            for neighbor in apac_neighbors[apac_added:]:
                if len(final_neighbors) >= top_n:
                    break
                final_neighbors.append(neighbor)
                apac_added += 1

        for neighbor in preferred_neighbors:
            if len(final_neighbors) >= top_n:
                break
            if whois_results[neighbor['addr']][2] != DIGITALOCEAN_ASN:  # Exclude non-APAC DigitalOcean
                final_neighbors.append(neighbor)

        for neighbor in other_neighbors:
            if len(final_neighbors) >= top_n:
                break
            if whois_results[neighbor['addr']][2] != DIGITALOCEAN_ASN:  # Exclude non-APAC DigitalOcean
                final_neighbors.append(neighbor)

        logger.info(f"Final selection: {len(final_neighbors)} neighbors, {apac_added} APAC")
        total_geo = self.geo_success + self.geo_failed
        if total_geo > 0:
            logger.info(f"Geolocation stats: {self.geo_success} successful, {self.geo_failed} failed ({self.geo_success/total_geo*100:.1f}% success)")
        return final_neighbors[:top_n]

    def _generate_rtt_histogram(self):
        rtts = [n['ping_rtt'] for n in self.neighbors_data if n['ping_rtt'] is not None]
        if rtts:
            plt.figure(figsize=(10, 6))
            plt.hist(rtts, bins=50, edgecolor='black')
            plt.xlabel('Ping RTT (ms)')
            plt.ylabel('Count')
            plt.title('Distribution of Neighbor Ping RTTs')
            plt.grid(True, alpha=0.3)
            plt.savefig(os.path.join(BASE_DIR, 'rtt_histogram.png'))
            plt.close()
            logger.info("Generated RTT histogram at rtt_histogram.png")

    def _print_summary(self):
        elapsed = time.time() - self.start_time
        self.perform_ping_tests()
        top_neighbors = self.get_top_neighbors_by_latency(50)
        whois_results = {n['addr']: self._get_whois_provider(n['addr']) for n in top_neighbors}
        self._generate_rtt_histogram()

        with open(os.path.join(BASE_DIR, 'neighbors.json'), 'w') as f:
            json.dump(self.neighbors_data, f, indent=2)
        logger.info("Exported neighbor data to neighbors.json")

        if self.high_loss_nodes:
            logger.info(f"High-loss nodes (>50% loss): {len(self.high_loss_nodes)}")
            logger.info(f"Examples: {', '.join(self.high_loss_nodes[:5])}{'...' if len(self.high_loss_nodes) > 5 else ''}")

        ip_mappings = {}
        logger.info("Resolving IPs for top neighbors...")
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(self.resolve_ip, neighbor['addr'].replace('tcp://', '').split(':')[0]): neighbor
                for neighbor in top_neighbors
            }
            for future in tqdm(as_completed(futures), total=len(futures), desc="Resolving IPs for table", unit="IP"):
                neighbor = futures[future]
                try:
                    ip_mappings[neighbor['addr']] = future.result(timeout=5)
                except Exception as e:
                    logger.warning(f"DNS resolution error for {neighbor['addr']}: {str(e)}")
                    ip_mappings[neighbor['addr']] = None

        original_formatter = console_handler.formatter
        console_handler.setFormatter(logging.Formatter('%(message)s'))

        try:
            border = self.colors.border_char * 65
            logger.info(f"\n{border}")
            logger.info(f"{self.colors.HEADER}{self.colors.v_border_char}{'NKN Network Crawl Summary'.center(63)}{self.colors.v_border_char}{self.colors.END}")
            logger.info(f"{border}\n")

            logger.info(f"Total Nodes Scanned: {len(self.visited_nodes)}")
            logger.info(f"Unique Neighbors Found: {len(self.neighbors_data)}")
            logger.info(f"Crawl Duration: {elapsed:.2f} seconds")
            if self.invalid_rtt_count > 0:
                logger.info(f"Skipped Neighbors (Invalid RTT <= 1.0ms): {self.invalid_rtt_count}")

            ping_type = 'TCP' if self.use_tcp_ping else 'ICMP'
            if top_neighbors:
                logger.info(f"\n{self.colors.BLUE}Top 50 Neighbors by Lowest {ping_type} Ping Latency and Variance:{self.colors.END}")
                rank_width = 6
                resolved_ip_width = max(12, max([len(n.get('resolved_ip', 'Unresolved')) for n in top_neighbors], default=0))
                address_width = max(20, max([len(n['addr'].replace('tcp://', '')) for n in top_neighbors], default=0))
                port_width = 6
                ping_rtt_width = max(14, max([len("Unreachable") if n['ping_rtt'] is None else len(f"{n['ping_rtt']:.1f}") for n in top_neighbors], default=0))
                variance_width = max(12, max([len("N/A") if n['ping_variance'] is None else len(f"{n['ping_variance']:.1f}") for n in top_neighbors], default=0))
                loss_width = max(10, max([len("N/A") if n['ping_loss'] is None else len(f"{n['ping_loss']:.1f}") for n in top_neighbors], default=0))
                location_width = max(20, max([len(self.get_geolocation(n.get('resolved_ip', '')) if n.get('resolved_ip') else "Unknown") for n in top_neighbors], default=0))
                apac_width = 6
                preferred_width = 15

                total_width = (rank_width + resolved_ip_width + address_width + port_width + ping_rtt_width +
                               variance_width + loss_width + location_width + apac_width + preferred_width + 18)
                separator = self.colors.sep_char * total_width

                header = (
                    f"{'Rank':<{rank_width}} "
                    f"{'Resolved IP':<{resolved_ip_width}} "
                    f"{'Address':<{address_width}} "
                    f"{'Port':<{port_width}} "
                    f"{f'{ping_type} Ping (ms)':<{ping_rtt_width}} "
                    f"{'Variance (ms)':<{variance_width}} "
                    f"{'Loss (%)':<{loss_width}} "
                    f"{'Location':<{location_width}} "
                    f"{'APAC':<{apac_width}} "
                    f"{'Region Priority':<{preferred_width}}"
                )
                logger.info(separator)
                logger.info(header)
                logger.info(separator)

                for i, neighbor in enumerate(top_neighbors, 1):
                    addr = neighbor['addr'].replace('tcp://', '')
                    resolved_ip = neighbor.get('resolved_ip', 'Unresolved')
                    port = str(neighbor['port'])
                    ping_rtt = "Unreachable" if neighbor['ping_rtt'] is None else f"{neighbor['ping_rtt']:.1f}"
                    ping_variance = "N/A" if neighbor['ping_variance'] is None else f"{neighbor['ping_variance']:.1f}"
                    ping_loss = "N/A" if neighbor['ping_loss'] is None else f"{neighbor['ping_loss']:.1f}"
                    location = self.get_geolocation(resolved_ip) if resolved_ip != "Unresolved" else "Unknown"
                    is_apac = self.is_apac_node(resolved_ip) if resolved_ip != "Unresolved" else False
                    is_preferred = self.is_preferred_node(resolved_ip) if resolved_ip != "Unresolved" else False
                    region_priority = "APAC" if is_apac else "Local" if is_preferred else "Other"
                    logger.info(
                        f"{i:<{rank_width}} "
                        f"{resolved_ip:<{resolved_ip_width}} "
                        f"{addr:<{address_width}} "
                        f"{port:<{port_width}} "
                        f"{ping_rtt:<{ping_rtt_width}} "
                        f"{ping_variance:<{variance_width}} "
                        f"{ping_loss:<{loss_width}} "
                        f"{location:<{location_width}} "
                        f"{str(is_apac):<{apac_width}} "
                        f"{region_priority:<{preferred_width}}"
                    )

                ping_rtts = [n['ping_rtt'] for n in top_neighbors if n['ping_rtt'] is not None]
                if ping_rtts:
                    min_rtt = min(ping_rtts)
                    max_rtt = max(ping_rtts)
                    logger.info(f"\nLatency Range: {min_rtt:.1f}ms to {max_rtt:.1f}ms")
                logger.info(separator)
            else:
                logger.info(f"\nNo neighbors with valid {ping_type} ping latencies found.")

            if top_neighbors:
                logger.info(f"\n{self.colors.BLUE}Analyzing Providers for Top {len(top_neighbors)} IPs...{self.colors.END}")
                providers = [whois_results[n['addr']][0][:27] for n in top_neighbors]
                asns = [whois_results[n['addr']][2] for n in top_neighbors]
                failed_lookups = [n['addr'].replace('tcp://', '').split(':')[0] for n in top_neighbors if not whois_results[n['addr']][1]]

                provider_counts = Counter(providers)
                provider_asn_pairs = list(zip(providers, asns))
                unique_pairs = sorted(set((p, a) for p, a in provider_asn_pairs), key=lambda x: provider_counts[x[0]], reverse=True)
                total_ips = sum(provider_counts.values())

                provider_width = max(15, max([len(p) for p in providers], default=0))
                asn_width = max(10, max([len(a) for a in asns], default=0))
                ips_width = max(5, max([len(str(provider_asn_pairs.count((p, a)))) for p, a in unique_pairs], default=0))
                provider_table_width = 65

                logger.info(f"\n{self.colors.GREEN}{self.colors.border_char * provider_table_width}{self.colors.END}")
                logger.info(f"{self.colors.GREEN}{self.colors.v_border_char}{'Top Hosting Providers'.center(provider_table_width-2)}{self.colors.v_border_char}{self.colors.END}")
                logger.info(f"{self.colors.GREEN}{self.colors.border_char * provider_table_width}{self.colors.END}")
                header = f"{'Provider':<{provider_width}} {'ASN':<{asn_width}} {'IPs':<{ips_width}}"
                logger.info(f"{self.colors.BLUE}{header}{self.colors.END}")
                logger.info(separator)
                for provider, asn in unique_pairs:
                    count = provider_asn_pairs.count((provider, asn))
                    logger.info(f"{provider:<{provider_width}} {asn:<{asn_width}} {count:<{ips_width}}")
                logger.info(separator)
                logger.info(f"Total IPs Analyzed: {total_ips}")

                if failed_lookups:
                    logger.info(f"\nWHOIS Lookup Failures: {len(failed_lookups)} IPs")
                    logger.info(f"Failed IPs: {', '.join(failed_lookups[:5])}{'...' if len(failed_lookups) > 5 else ''}")

            if top_neighbors:
                logger.info(f"\n{self.colors.BLUE}Top 25 Nodes for nkn.conf Neighbors:{self.colors.END}")
                rank_width = 6
                address_width = max(20, max([len(n['addr']) for n in top_neighbors[:25]], default=0))
                ping_rtt_width = max(14, max([len("Unreachable") if n['ping_rtt'] is None else len(f"{n['ping_rtt']:.1f}") for n in top_neighbors[:25]], default=0))
                score_width = max(8, max([len("N/A") if n.get('score', float('inf')) == float('inf') else len(f"{n['score']:.1f}") for n in top_neighbors[:25]], default=0))
                asn_width = max(10, max([len(whois_results[n['addr']][2]) for n in top_neighbors[:25]], default=0))
                location_width = max(20, max([len(self.get_geolocation(n.get('resolved_ip', '')) if n.get('resolved_ip') else "Unknown") for n in top_neighbors[:25]], default=0))
                apac_width = 6
                preferred_width = 15

                nkn_conf_width = rank_width + address_width + ping_rtt_width + score_width + asn_width + location_width + apac_width + preferred_width + 14
                separator = self.colors.sep_char * nkn_conf_width
                header = (
                    f"{'Rank':<{rank_width}} "
                    f"{'Address':<{address_width}} "
                    f"{f'{ping_type} Ping (ms)':<{ping_rtt_width}} "
                    f"{'Score':<{score_width}} "
                    f"{'ASN':<{asn_width}} "
                    f"{'Location':<{location_width}} "
                    f"{'APAC':<{apac_width}} "
                    f"{'Region Priority':<{preferred_width}}"
                )
                logger.info(separator)
                logger.info(header)
                logger.info(separator)
                for i, neighbor in enumerate(top_neighbors[:25], 1):
                    addr = neighbor['addr']
                    ping_rtt = "Unreachable" if neighbor['ping_rtt'] is None else f"{neighbor['ping_rtt']:.1f}"
                    score = "N/A" if neighbor.get('score', float('inf')) == float('inf') else f"{neighbor['score']:.1f}"
                    resolved_ip = ip_mappings.get(addr, neighbor.get('resolved_ip'))
                    asn = whois_results[addr][2]
                    location = self.get_geolocation(resolved_ip) if resolved_ip else "Unknown"
                    is_apac = self.is_apac_node(resolved_ip) if resolved_ip else False
                    is_preferred = self.is_preferred_node(resolved_ip) if resolved_ip else False
                    region_priority = "APAC" if is_apac else "Local" if is_preferred else "Other"
                    logger.info(
                        f"{i:<{rank_width}} "
                        f"{addr:<{address_width}} "
                        f"{ping_rtt:<{ping_rtt_width}} "
                        f"{score:<{score_width}} "
                        f"{asn:<{asn_width}} "
                        f"{location:<{location_width}} "
                        f"{str(is_apac):<{apac_width}} "
                        f"{region_priority:<{preferred_width}}"
                    )
                logger.info(separator)

                logger.info(f"\nUse in nkn.conf:")
                relay_addrs = []
                for neighbor in top_neighbors[:25]:
                    addr = neighbor['addr'].replace('tcp://', '')
                    ip = addr.split(':')[0]
                    port = 30001
                    node_id = neighbor.get('id')
                    if node_id:
                        relay_addr = f"/ip4/{ip}/tcp/{port}/p2p/{node_id}"
                        relay_addrs.append(relay_addr)
                    else:
                        logger.warning(f"Skipping {addr}:{port} due to missing node ID")
                if relay_addrs:
                    logger.info('  "RelayAddrs": [')
                    for i, addr in enumerate(relay_addrs):
                        comma = ',' if i < len(relay_addrs) - 1 else ''
                        logger.info(f'    "{addr}"{comma}')
                    logger.info('  ],')
                else:
                    logger.info('  "RelayAddrs": [],')

            indent = ""
            completion_border = (self.colors.border_char * 63)[:63]
            inner_width = 61
            top_border_line = f"{indent}{self.colors.GREEN}{completion_border}{self.colors.END}"
            text_line = f"{indent}{self.colors.GREEN}{self.colors.v_border_char}{' Crawl Completed Successfully! '.center(inner_width)}{self.colors.v_border_char}{self.colors.END}"
            bottom_border_line = f"{indent}{self.colors.GREEN}{completion_border}{self.colors.END}"
            logger.info(f"\n{top_border_line}")
            logger.info(text_line)
            logger.info(bottom_border_line)
            logger.info("")
        finally:
            console_handler.setFormatter(original_formatter)

    def handle_shutdown(self, signum, frame):
        logger.info("Received shutdown signal. Stopping crawl and generating summary...")
        self.running = False
        self._print_summary()
        self.geo_reader_city.close()
        self.geo_reader_asn.close()
        with builtins.open(os.path.join(BASE_DIR, 'geo_cache.pkl'), 'wb') as f:
            pickle.dump(self.geo_cache, f)
        with builtins.open(os.path.join(BASE_DIR, 'whois_cache.pkl'), 'wb') as f:
            pickle.dump(self.whois_local_cache, f)
        sys.exit(0)

    def __del__(self):
        try:
            self.geo_reader_city.close()
            self.geo_reader_asn.close()
        except AttributeError:
            pass

def validate_seed(url: str, node_id: str) -> bool:
    try:
        response = requests.post(
            url,
            json={"jsonrpc": "2.0", "method": "getneighbor", "params": {"id": node_id}, "id": 1},
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        if response.status_code == 200:
            try:
                data = response.json()
                if 'result' in data:
                    logger.debug(f"Validated seed: {url}")
                    return True
                else:
                    logger.warning(f"Seed validation failed for {url}: No 'result' in response")
                    return False
            except ValueError:
                logger.warning(f"Seed validation failed for {url}: Invalid JSON response")
                return False
        else:
            logger.warning(f"Seed validation failed for {url}: Status {response.status_code}")
            return False
    except requests.RequestException as e:
        logger.warning(f"Seed validation failed for {url}: {str(e)}")
        return False

def load_apac_seeds() -> List[Tuple[str, str]]:
    apac_seed_file = os.path.join(BASE_DIR, 'apac_seeds.json')
    apac_seeds = []
    try:
        if os.path.exists(apac_seed_file):
            with open(apac_seed_file, 'r') as f:
                apac_seeds = json.load(f)
                logger.info(f"Loaded {len(apac_seeds)} APAC seeds from {apac_seed_file}")
        else:
            logger.warning(f"APAC seed file {apac_seed_file} not found. Please create it with valid APAC seeds.")
    except Exception as e:
        logger.error(f"Failed to load APAC seeds from {apac_seed_file}: {str(e)}")
    
    valid_seeds = []
    for seed in apac_seeds:
        url = seed.get('url')
        node_id = seed.get('id')
        if not url or not node_id:
            logger.warning(f"Invalid seed format: {seed}")
            continue
        if validate_seed(url, node_id):
            valid_seeds.append((url, node_id))
    logger.info(f"Validated {len(valid_seeds)} of {len(apac_seeds)} APAC seeds")
    if not valid_seeds:
        logger.warning("No valid APAC seeds found. Create apac_seeds.json with seeds from https://forum.nkn.org")
    return valid_seeds

def main():
    parser = argparse.ArgumentParser(description="NKN Network Crawler")
    parser.add_argument('--no-color', action='store_true', help="Disable colored output and use ASCII characters")
    parser.add_argument('--debug-geo', action='store_true', help="Enable debug logging for geolocation lookups")
    parser.add_argument('--clear-cache', action='store_true', help="Clear geolocation and WHOIS caches before starting")
    parser.add_argument('--wallet', default='YOUR_WALLET_ADDRESS', help="NKN wallet address")
    args = parser.parse_args()

    crawler = NKNCrawler(
        target_neighbors=5000,
        use_tcp_ping=True,
        use_color=not args.no_color,
        debug_geo=args.debug_geo,
        clear_cache=args.clear_cache
    )
    signal.signal(signal.SIGINT, crawler.handle_shutdown)
    signal.signal(signal.SIGTERM, crawler.handle_shutdown)

    wallet_address = args.wallet
    logger.info(f"Starting NKN network crawl for wallet: {wallet_address}")
    logger.info("Collecting up to 5000 neighbors.")

    default_seeds = [
        ("http://mainnet-seed-0001.nkn.org:30003", "84789f30482bb9570fc40a619525d64d204af784f45d88859aaeca96e57efec7"),
        ("http://mainnet-seed-0010.nkn.org:30003", "84789f30482bb9570fc40a619525d64d204af784f45d88859aaeca96e57efec7"),
        ("http://mainnet-seed-0020.nkn.org:30003", "84789f30482bb9570fc40a619525d64d204af784f45d88859aaeca96e57efec7"),
        ("http://mainnet-seed-0030.nkn.org:30003", "84789f30482bb9570fc40a619525d64d204af784f45d88859aaeca96e57efec7"),
        ("http://mainnet-seed-0044.nkn.org:30003", "84789f30482bb9570fc40a619525d64d204af784f45d88859aaeca96e57efec7"),
    ]

    apac_seeds = load_apac_seeds()
    if not apac_seeds:
        logger.warning("No valid APAC seeds found. Create apac_seeds.json with valid seeds from https://forum.nkn.org")

    seed_nodes = apac_seeds + default_seeds  # Prioritize APAC seeds
    valid_seeds = []
    for url, node_id in seed_nodes:
        if validate_seed(url, node_id):
            valid_seeds.append((url, node_id))
        else:
            logger.warning(f"Seed {url} is invalid and will be skipped")

    if not valid_seeds:
        logger.error("No valid seed nodes available. Please check seed URLs and network connectivity. Exiting.")
        sys.exit(1)

    apac_valid_seeds = [(url, node_id) for url, node_id in valid_seeds if any(country in url for country in crawler.apac_countries) or url in [s[0] for s in apac_seeds]]
    logger.info(f"Validated {len(valid_seeds)} seed nodes, {len(apac_valid_seeds)} APAC: {[url for url, _ in valid_seeds]}")

    try:
        for node_url, node_id in apac_valid_seeds + [s for s in valid_seeds if s not in apac_valid_seeds]:
            if not crawler.running or len(crawler.neighbors_data) >= crawler.target_neighbors:
                break
            logger.info(f"Starting crawl from seed: {node_url}")
            crawler.geo_queue.put((node_url, node_id, 0))
            crawler.crawl_nodes_concurrently()
        
        # Count APAC nodes explicitly to avoid syntax issues
        apac_count = len([n for n in crawler.neighbors_data if n.get('resolved_ip') and crawler.is_apac_node(n['resolved_ip'])])
        logger.info(f"Total APAC nodes found: {apac_count}")
        if apac_count == 0:
            logger.warning("No APAC nodes detected. Verify apac_seeds.json or source new seeds from https://forum.nkn.org")
    except Exception as e:
        logger.error(f"Crawl failed: {str(e)}")
    finally:
        crawler._print_summary()
        crawler.geo_reader_city.close()
        crawler.geo_reader_asn.close()
        with builtins.open(os.path.join(BASE_DIR, 'geo_cache.pkl'), 'wb') as f:
            pickle.dump(crawler.geo_cache, f)
        with builtins.open(os.path.join(BASE_DIR, 'whois_cache.pkl'), 'wb') as f:
            pickle.dump(crawler.whois_local_cache, f)

if __name__ == "__main__":
    main()
