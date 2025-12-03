# MISP IDS Integration

**Automated Threat Intelligence Integration**

## Overview
Automated IOC ingestion into Suricata IDS with rule generation, real-time detection, and dashboard visualization.

## Features
- Automated IOC → Suricata rule conversion  
- Real-time detection monitoring  
- Local visualization dashboard  
- Fast deployment  
- Simple architecture

## Architecture
MISP → Python Scripts → Suricata Rules → Detection → Dashboard

# Quick Start

## Installation
```
sudo apt install -y suricata python3 python3-pip
```
## Setup
```
git clone https://github.com/ODaghlas03/MISP-IDS-Integration.git
cd MISP-IDS-Integration
 ```
## Load Rules Into Suricata

### Add to suricata.yaml under rule-files:
```
- /etc/suricata/rules/misp/misp-iocs.rules
sudo systemctl restart suricata
```

## Usage
### Update IOCs

```
python3 scripts/misp_to_suricata.py
```
## Generate Statistics
```
python3 scripts/generate_dashboard_data.py
```
## Monitor Alerts
```
sudo tail -f /var/log/suricata/fast.log
```
## Dashboard
```
dashboard/index.html
```
## Project Structure
scripts/         Automation scripts
rules/           Suricata rules + stats.json
config/          Suricata config
dashboard/       Web UI

## Technologies
MISP, Suricata, Python 3, HTML/JS/CSS

### Author 
Omar Daghlas - Birzeit University
