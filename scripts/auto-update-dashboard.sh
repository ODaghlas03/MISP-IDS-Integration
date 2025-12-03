#!/bin/bash
while true; do
    /opt/misp-suricata/venv/bin/python3 /opt/misp-suricata/generate_dashboard_data.py
    cp /var/www/html/ioc-dashboard/data.json /var/www/MISP/app/webroot/dashboard/data.json
    sleep 30  # Update every 10 seconds
done
