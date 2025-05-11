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
1. See INSTALL file

### Option 2: Use Prebuilt Binary (Linux)
1. Download the latest binary from the [Releases](https://github.com/havok2/nkn-scan/releases) page.
2. Extract if zipped: `unzip crawler.zip`
3. Make executable: `chmod +x crawler`
4. Install `hping3`: `sudo apt-get install hping3`
5. Create a `geoip/` directory and place `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` in it (download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)).
6. Run: `./crawler --wallet YOUR_WALLET_ADDRESS`
