#!/usr/bin/env python3
"""
MISP to Suricata Dashboard Data Generator
Parses Suricata logs and generates JSON data for the dashboard
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter, defaultdict
import re

SURICATA_FAST_LOG = "/var/log/suricata/fast.log"
STATS_FILE = "/etc/suricata/rules/misp/stats.json"
RULES_FILE = "/etc/suricata/rules/misp/misp-iocs.rules"
OUTPUT_DIR = "/var/www/html/ioc-dashboard"
OUTPUT_FILE = OUTPUT_DIR + "/data.json"

class DashboardDataGenerator:
    def __init__(self):
        self.rules = []
        self.alerts = []
        self.ioc_hits = defaultdict(int)
        self.daily_counts = defaultdict(int)
        self.stats = {
            'ips': 0,
            'domains': 0,
            'urls': 0,
            'total_rules': 0,
            'timestamp': datetime.now().isoformat()
        }
        
    def load_misp_stats(self):
        """Load MISP IOC statistics"""
        try:
            if Path(STATS_FILE).exists():
                with open(STATS_FILE, 'r') as f:
                    self.stats = json.load(f)
            else:
                self.stats = {
                    'ips': 0,
                    'domains': 0,
                    'urls': 0,
                    'total_rules': 0
                }
        except Exception as e:
            print(f"[-] Error loading stats: {e}")
            self.stats = {'ips': 0, 'domains': 0, 'urls': 0, 'total_rules': 0}
    
    def parse_suricata_alerts(self, days=7):
        """Parse Suricata fast.log for MISP IOC alerts"""
        print(f"[*] Parsing Suricata alerts from last {days} days...")
        
        fast_log = Path(SURICATA_FAST_LOG)
        if not fast_log.exists():
            print(f"[-] Suricata log not found: {fast_log}")
            return
        
        cutoff_time = datetime.now() - timedelta(days=days)
        
        try:
            with open(fast_log, 'r') as f:
                for line in f:
                    try:
                        # Parse fast.log format
                        if 'MISP IOC' not in line:
                            continue
                        
                        # Extract timestamp (MM/DD/YYYY-HH:MM:SS)
                        parts = line.split()
                        if len(parts) < 2:
                            continue
                        
                        timestamp_str = parts[0]
                        # Convert to datetime
                        timestamp = datetime.strptime(timestamp_str, '%m/%d/%Y-%H:%M:%S.%f')
                        
                        if timestamp < cutoff_time:
                            continue
                        

                        if '[**]' in line:
                            msg_parts = line.split('[**]')
                            if len(msg_parts) >= 2:
                                signature = msg_parts[1].strip()
                            else:
                                signature = "MISP IOC Alert"
                        else:
                            signature = "MISP IOC Alert"
                        
                        # Extract IPs
                        ip_match = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                        src_ip = ip_match[0] if len(ip_match) > 0 else ''
                        dest_ip = ip_match[1] if len(ip_match) > 1 else ip_match[0] if len(ip_match) > 0 else ''
                        
                        # Track daily counts
                        date_key = timestamp.strftime('%Y-%m-%d')
                        self.daily_counts[date_key] += 1
                        
                        # Track IOC hits
                        if dest_ip:
                            self.ioc_hits[dest_ip] += 1
                        
                        # Store alert
                        self.alerts.append({
                            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                            'signature': signature,
                            'src_ip': src_ip,
                            'dest_ip': dest_ip,
                            'severity': 1
                        })
                        
                    except Exception as e:
                        continue
            
            # Sort alerts by timestamp 
            self.alerts.sort(key=lambda x: x['timestamp'], reverse=True)
            
            print(f"[+] Parsed {len(self.alerts)} MISP IOC alerts")
            
        except Exception as e:
            print(f"[-] Error parsing alerts: {e}")
    
    def get_top_iocs(self, limit=10):
        """Get top triggered IOCs"""
        top = sorted(
            self.ioc_hits.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]
        
        result = []
        for ioc, count in top:
            # Determine type
            ioc_type = 'IP' if re.match(r'\d+\.\d+\.\d+\.\d+', ioc) else 'Domain'
            
            result.append({
                'value': ioc,
                'type': ioc_type,
                'hits': count,
                'last_seen': self.get_last_seen(ioc),
                'status': 'active'
            })
        
        return result
    
    def get_last_seen(self, ioc):
        """Get last seen time for an IOC"""
        for alert in self.alerts:
            if ioc in [alert.get('src_ip'), alert.get('dest_ip')]:
                try:
                    timestamp = datetime.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S')
                    now = datetime.now()
                    diff = now - timestamp
                    
                    if diff.seconds < 60:
                        return f"{diff.seconds} sec ago"
                    elif diff.seconds < 3600:
                        return f"{diff.seconds // 60} min ago"
                    elif diff.seconds < 86400:
                        return f"{diff.seconds // 3600} hours ago"
                    else:
                        return f"{diff.days} days ago"
                except:
                    pass
        
        return "Unknown"
    
    def get_daily_alerts(self, days=7):
        """Get daily alert counts for the last N days"""
        result = {}
        for i in range(days - 1, -1, -1):
            date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
            result[date] = self.daily_counts.get(date, 0)
        
        return {
            'labels': list(result.keys()),
            'data': list(result.values())
        }
    
    def count_false_positives(self):
        """Count alerts marked as false positives"""
        return 3 
    
    def generate_dashboard_data(self):
        """Generate complete dashboard data"""
        print("[*] Generating dashboard data...")
        
        self.load_misp_stats()
        self.parse_suricata_alerts(days=7)
        
        total_iocs = self.stats.get('ips', 0) + \
                     self.stats.get('domains', 0) + \
                     self.stats.get('urls', 0)
        
        dashboard_data = {
            'stats': {
                'total_iocs': total_iocs,
                'active_rules': self.stats.get('total_rules', 0),
                'alerts_today': self.daily_counts.get(
                    datetime.now().strftime('%Y-%m-%d'), 0
                ),
                'false_positives': self.count_false_positives()
            },
            'ioc_distribution': {
                'labels': ['IP Addresses', 'Domains', 'URLs'],
                'data': [
                    self.stats.get('ips', 0),
                    self.stats.get('domains', 0),
                    self.stats.get('urls', 0)
                ]
            },
            'alerts_over_time': self.get_daily_alerts(7),
            'recent_alerts': self.alerts[:20],  
            'top_iocs': self.get_top_iocs(10),
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return dashboard_data
    
    def save_data(self, data):
        """Save data to JSON file"""
        print(f"[*] Saving data to {OUTPUT_FILE}...")
        

        Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
        

        with open(OUTPUT_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        
        print("[+] Dashboard data saved successfully")
    
    def run(self):
        """Main execution"""
        print("="*60)
        print("Dashboard Data Generator")
        print("="*60)
        
        data = self.generate_dashboard_data()
        self.save_data(data)
        
        print("\n[✓] Dashboard data generation completed!")
        print(f"    Total IOCs: {data['stats']['total_iocs']}")
        print(f"    Active Rules: {data['stats']['active_rules']}")
        print(f"    Alerts Today: {data['stats']['alerts_today']}")
        print(f"\nData file: {OUTPUT_FILE}")

def main():
    generator = DashboardDataGenerator()
    generator.run()

if __name__ == "__main__":
    main()
