#!/usr/bin/env python3
"""
MISP to Suricata IOC Automation Script
Extracts IOCs from MISP and generates Suricata rules with versioning
"""

import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
import hashlib
import argparse

try:
    from pymisp import PyMISP
except ImportError:
    print("Error: pymisp not installed. Run: pip3 install pymisp")
    sys.exit(1)

# Configuration
MISP_URL = "http://10.211.55.3"
MISP_KEY = "OI0CFMUirkJEwnl528f4S1JpgGTfWb8JQ7WA2lSB"
MISP_VERIFYCERT = False

# Paths
RULES_DIR = Path("/etc/suricata/rules/misp")
BACKUP_DIR = Path("/etc/suricata/rules/misp/backups")
RULES_FILE = RULES_DIR / "misp-iocs.rules"
VERSION_FILE = RULES_DIR / "version.json"
STATS_FILE = RULES_DIR / "stats.json"

# Rule settings
SID_START = 5000000 
RULE_PRIORITY = 1

class MISPToSuricata:
    def __init__(self):
        self.misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
        self.rules = []
        self.sid_counter = SID_START
        self.stats = {
            'ips': 0,
            'domains': 0,
            'urls': 0,
            'total_rules': 0,
            'timestamp': datetime.now().isoformat()
        }
        
    def setup_directories(self):
        """Create necessary directories"""
        RULES_DIR.mkdir(parents=True, exist_ok=True)
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        print(f"[+] Directories created: {RULES_DIR}")
        
    def fetch_iocs(self, days=30):
        """Fetch IOCs from MISP events"""
        print(f"[*] Fetching IOCs from MISP (last {days} days)...")
        
        try:
            # Search for recent events
            events = self.misp.search(
                controller='events',
                published=True,
                timestamp=f'{days}d',
                pythonify=True
            )
            
            print(f"[+] Found {len(events)} events")
            
            iocs = {
                'ips': set(),
                'domains': set(),
                'urls': set()
            }
            
            for event in events:
                for attribute in event.attributes:
                    if not attribute.to_ids:  
                        continue
                        
                    attr_type = attribute.type
                    value = attribute.value
                    
                    # Extract IPs
                    if attr_type in ['ip-dst', 'ip-src']:
                        iocs['ips'].add(value)
                        
                    # Extract domains
                    elif attr_type in ['domain', 'hostname']:
                        iocs['domains'].add(value)
                        
                    # Extract URLs
                    elif attr_type in ['url', 'uri']:
                        iocs['urls'].add(value)
            
            self.stats['ips'] = len(iocs['ips'])
            self.stats['domains'] = len(iocs['domains'])
            self.stats['urls'] = len(iocs['urls'])
            
            print(f"[+] Extracted IOCs:")
            print(f"    - IPs: {len(iocs['ips'])}")
            print(f"    - Domains: {len(iocs['domains'])}")
            print(f"    - URLs: {len(iocs['urls'])}")
            
            return iocs
            
        except Exception as e:
            print(f"[-] Error fetching IOCs: {e}")
            return None
    
    def generate_ip_rule(self, ip):
        """Generate Suricata rule for IP"""
        sid = self.sid_counter
        self.sid_counter += 1
        
        rule = f'alert ip any any -> {ip} any (msg:"MISP IOC: Malicious IP {ip}"; ' \
               f'sid:{sid}; priority:{RULE_PRIORITY}; ' \
               f'metadata:created {datetime.now().strftime("%Y-%m-%d")}; ' \
               f'classtype:trojan-activity; rev:1;)'
        
        return rule
    
    def generate_domain_rule(self, domain):
        """Generate Suricata rule for domain"""
        sid = self.sid_counter
        self.sid_counter += 1
        
        # DNS query rule
        rule = f'alert dns any any -> any any (msg:"MISP IOC: Malicious Domain {domain}"; ' \
               f'dns.query; content:"{domain}"; nocase; ' \
               f'sid:{sid}; priority:{RULE_PRIORITY}; ' \
               f'metadata:created {datetime.now().strftime("%Y-%m-%d")}; ' \
               f'classtype:trojan-activity; rev:1;)'
        
        return rule
    
    def generate_http_domain_rule(self, domain):
        """Generate HTTP/TLS rule for domain"""
        sid = self.sid_counter
        self.sid_counter += 1
        
        rule = f'alert tls any any -> any any (msg:"MISP IOC: TLS to Malicious Domain {domain}"; ' \
               f'tls.sni; content:"{domain}"; nocase; ' \
               f'sid:{sid}; priority:{RULE_PRIORITY}; ' \
               f'metadata:created {datetime.now().strftime("%Y-%m-%d")}; ' \
               f'classtype:trojan-activity; rev:1;)'
        
        return rule
    
    def generate_url_rule(self, url):
        """Generate Suricata rule for URL"""
        sid = self.sid_counter
        self.sid_counter += 1
        
        # Extract path from URL
        if '://' in url:
            path = url.split('://', 1)[1]
            if '/' in path:
                path = '/' + path.split('/', 1)[1]
            else:
                path = '/'
        else:
            path = url
        
        rule = f'alert http any any -> any any (msg:"MISP IOC: Malicious URL {url[:50]}"; ' \
               f'http.uri; content:"{path}"; nocase; ' \
               f'sid:{sid}; priority:{RULE_PRIORITY}; ' \
               f'metadata:created {datetime.now().strftime("%Y-%m-%d")}; ' \
               f'classtype:trojan-activity; rev:1;)'
        
        return rule
    
    def generate_rules(self, iocs):
        """Generate all Suricata rules from IOCs"""
        print("[*] Generating Suricata rules...")
        
        rules = []
        
        # Generate IP rules
        for ip in sorted(iocs['ips']):
            rules.append(self.generate_ip_rule(ip))
        
        # Generate domain rules (DNS and HTTP/TLS)
        for domain in sorted(iocs['domains']):
            rules.append(self.generate_domain_rule(domain))
            rules.append(self.generate_http_domain_rule(domain))
        
        # Generate URL rules
        for url in sorted(iocs['urls']):
            rules.append(self.generate_url_rule(url))
        
        self.stats['total_rules'] = len(rules)
        print(f"[+] Generated {len(rules)} Suricata rules")
        
        return rules
    
    def backup_current_rules(self):
        """Backup current rules file"""
        if RULES_FILE.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = BACKUP_DIR / f"misp-iocs_{timestamp}.rules"
            shutil.copy2(RULES_FILE, backup_file)
            print(f"[+] Backed up current rules to: {backup_file}")
            
            # Keep only last 10 backups
            backups = sorted(BACKUP_DIR.glob("misp-iocs_*.rules"))
            if len(backups) > 10:
                for old_backup in backups[:-10]:
                    old_backup.unlink()
                    print(f"[+] Removed old backup: {old_backup}")
    
    def calculate_checksum(self, content):
        """Calculate SHA256 checksum"""
        return hashlib.sha256(content.encode()).hexdigest()
    
    def save_rules(self, rules):
        """Save rules to file with versioning"""
        print(f"[*] Saving rules to {RULES_FILE}...")
        
        # Create backup first
        self.backup_current_rules()
        
        # Write new rules
        content = "# MISP IOC Rules\n"
        content += f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        content += f"# Total Rules: {len(rules)}\n\n"
        content += "\n".join(rules)
        
        with open(RULES_FILE, 'w') as f:
            f.write(content)
        
        # Save version info
        version_info = {
            'timestamp': datetime.now().isoformat(),
            'checksum': self.calculate_checksum(content),
            'rule_count': len(rules),
            'stats': self.stats
        }
        
        with open(VERSION_FILE, 'w') as f:
            json.dump(version_info, f, indent=2)
        
        print(f"[+] Rules saved successfully")
        print(f"[+] Checksum: {version_info['checksum'][:16]}...")
    
    def save_stats(self):
        """Save statistics"""
        with open(STATS_FILE, 'w') as f:
            json.dump(self.stats, f, indent=2)
        print(f"[+] Statistics saved to {STATS_FILE}")
    
    def reload_suricata(self):
        """Reload Suricata rules"""
        print("[*] Reloading Suricata...")
        ret = os.system("sudo suricatasc -c reload-rules")
        if ret == 0:
            print("[+] Suricata rules reloaded successfully")
        else:
            print("[-] Failed to reload Suricata. Try: sudo systemctl restart suricata")
    
    def list_backups(self):
        """List available backups"""
        backups = sorted(BACKUP_DIR.glob("misp-iocs_*.rules"), reverse=True)
        
        if not backups:
            print("[!] No backups found")
            return
        
        print("\n[+] Available backups:")
        for i, backup in enumerate(backups, 1):
            size = backup.stat().st_size
            mtime = datetime.fromtimestamp(backup.stat().st_mtime)
            print(f"  {i}. {backup.name} ({size} bytes, {mtime.strftime('%Y-%m-%d %H:%M:%S')})")
    
    def rollback(self, backup_name=None):
        """Rollback to a previous version"""
        if backup_name:
            backup_file = BACKUP_DIR / backup_name
        else:
            # Use most recent backup
            backups = sorted(BACKUP_DIR.glob("misp-iocs_*.rules"), reverse=True)
            if not backups:
                print("[-] No backups available for rollback")
                return False
            backup_file = backups[0]
        
        if not backup_file.exists():
            print(f"[-] Backup file not found: {backup_file}")
            return False
        
        print(f"[*] Rolling back to: {backup_file.name}")
        shutil.copy2(backup_file, RULES_FILE)
        print("[+] Rollback successful")
        
        self.reload_suricata()
        return True
    
    def run(self, days=30):
        """Main execution"""
        print("="*60)
        print("MISP to Suricata IOC Automation")
        print("="*60)
        
        self.setup_directories()
        
        # Fetch IOCs
        iocs = self.fetch_iocs(days)
        if not iocs:
            print("[-] No IOCs fetched. Exiting.")
            return False
        
        # Generate rules
        rules = self.generate_rules(iocs)
        
        # Save rules
        self.save_rules(rules)
        self.save_stats()
        
        # Reload Suricata
        self.reload_suricata()
        
        print("\n[✓] IOC update completed successfully!")
        return True

def main():
    parser = argparse.ArgumentParser(description='MISP to Suricata IOC Automation')
    parser.add_argument('-d', '--days', type=int, default=30,
                        help='Number of days to fetch IOCs (default: 30)')
    parser.add_argument('-l', '--list-backups', action='store_true',
                        help='List available backups')
    parser.add_argument('-r', '--rollback', nargs='?', const=True,
                        help='Rollback to previous version (optionally specify backup file)')
    parser.add_argument('--no-reload', action='store_true',
                        help='Do not reload Suricata after updating rules')
    
    args = parser.parse_args()
    
    converter = MISPToSuricata()
    
    if args.list_backups:
        converter.list_backups()
        return
    
    if args.rollback:
        backup_name = args.rollback if isinstance(args.rollback, str) else None
        converter.rollback(backup_name)
        return
    

    converter.run(args.days)

if __name__ == "__main__":
    main()
