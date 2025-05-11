# NKN Network Crawler

A Python script to crawl the NKN network, prioritize APAC nodes, and generate optimized `RelayAddrs` for `nkn.conf`.

## Features
- Crawls up to 5,000 NKN nodes with APAC seed prioritization.
- Pings 3,000 nodes using TCP (`hping3`) with ICMP fallback.
- Prioritizes APAC nodes (e.g., JP, SG, HK) in scoring.
- Generates `neighbors.json`, RTT histogram, and `nkn.conf` `RelayAddrs`.

## Prerequisites
- **System**: Linux (due to `hping3` and `whois`).
- **Python**: 3.6+.
- **GeoLite2 Databases**: [MaxMind GeoLite2 City and ASN](https://www.maxmind.com) (free account required).
- **Packages**:
  ```bash
  apt-get update
  apt-get install hping3 whois python3-pip
  pip3 install -r requirements.txt
