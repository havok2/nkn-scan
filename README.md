# NKN Crawler

A Python script to crawl the NKN (New Kind of Network) network, discover neighbors, perform latency tests, and optimize neighbor selection for NKN mining nodes. The script prioritizes low-latency, stable nodes (especially in APAC regions) and generates a configuration for `nkn.conf`.

## Features
- Crawls NKN network to discover up to 5000 neighbors.
- Performs TCP or ICMP ping tests to measure latency, variance, and packet loss.
- Prioritizes APAC and low-latency nodes for better mining performance.
- Generates a detailed summary with geolocation and provider analysis.
- Outputs `RelayAddrs` for `nkn.conf` to optimize NKN node configuration.
- Supports caching for geolocation and WHOIS lookups to improve performance.
- Creates an RTT histogram for latency analysis.

## Prerequisites
- **Python 3.6+**
- **System Dependencies**:
  - `hping3` (for TCP pings): `sudo apt-get install hping3` (Debian/Ubuntu)
- **GeoLite2 Databases**:
  - Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
  - Place them in the `geoip/` directory.
- **Optional**:
  - An [ipinfo.io](https://ipinfo.io) API token for enhanced geolocation (set as `IPINFO_TOKEN` environment variable).

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/nkn-crawler.git
   cd nkn-crawler
   python3 crawler.py
