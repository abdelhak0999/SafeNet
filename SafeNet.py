import nmap
import mysql.connector
import datetime
import sys
import argparse
import requests
import json

# --- DYNAMIC ARGUMENT PARSING ---
parser = argparse.ArgumentParser(description="Dynamic Network Inventory Scanner")
parser.add_argument("--network", type=str, default="192.168.122.0/24", 
                    help="The subnet to scan (e.g., 192.168.1.0/24)")
parser.add_argument("--password", type=str, default="", 
                    help="MariaDB root password")
parser.add_argument("--mode", type=str, choices=['fast', 'full'], default='fast', 
                    help="Scan mode: 'fast' (top 100 ports) or 'full' (all 65535 ports)")

args = parser.parse_args()

# Assign arguments to global variables used by the functions
NETWORK = args.network 
DB_PASSWORD = args.password
SCAN_MODE = args.mode


# --- FUNCTION 1: CONNECT TO DATABASE ---
def connect_db():
    try:
        conn = mysql.connector.connect(
            host="127.0.0.1",
            user="root",
            password=DB_PASSWORD,
            database="inventory_db",
        )
        print("database connected successfully")
        return conn
    except mysql.connector.Error as e:
        print(f"error connecting to mariadb: {e}")
        sys.exit(1)


# --- FUNCTION 2: DYNAMIC NETWORK SCAN ---
def scan_network():
    print(f"starting scan in {SCAN_MODE} mode...")
    nm = nmap.PortScanner() 

    # Base flags: OS detection, version detection, SYN scan, aggressive timing
    base_args = '-O --osscan-guess -sS -sV -T4 --osscan-limit'
    
    # Dynamically change port range based on --mode argument
    if SCAN_MODE == 'fast':
        final_args = base_args + ' -F'  # -F: Scan only the top 100 ports (fast)
    else:
        final_args = base_args + ' -p-' # -p-: Scan ALL 65535 ports (full/deep)

    # Execute the scan
    nm.scan(hosts=NETWORK, arguments=final_args)

    devices = []  

    for host in nm.all_hosts():
        ip = host
        mac = nm[host]['addresses'].get('mac', 'UNKNOWN') 
        hostname = nm[host].hostname() 

        os_guess = "Undetected"
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            os_guess = nm[host]['osmatch'][0]['name']

        # Extract Service Versions for CVE Checking
        services = []
        if mac != 'UNKNOWN':
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        service_name = nm[host][proto][port]['name']
                        service_version = nm[host][proto][port]['version']
                        if service_version and service_version != "":
                            services.append({
                                'port': port,
                                'protocol': proto,
                                'service': service_name,
                                'version': service_version
                            })

            device = {
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'os': os_guess,
                'services': services
            }
            
            # DEBUG PRINT TO PROVE OS IS BEING CAPTURED
            print(f"    [DEBUG] Storing OS for {ip}: {os_guess}")
            
            devices.append(device)
            
            print(f"    Found: {ip} | MAC: {mac} | OS: {os_guess}")
            if services:
                service_info = "; ".join([f"{s['service']}:{s['version']} (port {s['port']})" for s in services])
                print(f"        -> Services: {service_info}")

    print(f" scan complete. found {len(devices)} trackable devices.\n")
    return devices


# --- FUNCTION 3: RECONCILE WITH DATABASE ---
def reconcile_inventory(conn, found_devices):
    print("Reconciling inventory with database...")
    cursor = conn.cursor()
    
    intrusion_count = 0
    new_device_count = 0
    
    for device in found_devices:
        os_guess = device.get('os', 'Undetected')
        mac = device['mac']
        ip = device['ip']
        hostname = device['hostname']
        
        cursor.execute("SELECT expected_ip FROM authorized_devices WHERE mac_address = %s", (mac,))
        result = cursor.fetchone()
        
        if result:
            expected_ip = result[0]
            if ip == expected_ip:
                cursor.execute("UPDATE authorized_devices SET last_seen = NOW() WHERE mac_address = %s", (mac,))
                print(f"✅ VALIDATED: {mac} is at {ip}")
            else:
                # UPDATE with OS included
                cursor.execute("""
                    UPDATE authorized_devices 
                    SET expected_ip = %s, os = %s, status = 'Departed', last_seen = NOW() 
                    WHERE mac_address = %s
                """, (ip, os_guess, mac))
                cursor.execute("""
                    INSERT INTO audit_logs (mac_address, event_type, message) 
                    VALUES (%s, 'IP_MOVED', %s)
                """, (mac, f"Moved from {expected_ip} to {ip}"))
                print(f"⚠️ DEPARTED: {mac} moved to {ip}")
        else:
            cursor.execute("SELECT mac_address FROM authorized_devices WHERE expected_ip = %s", (ip,))
            ip_owner = cursor.fetchone()
            
            if ip_owner:
                cursor.execute("""
                    INSERT INTO audit_logs (mac_address, event_type, message) 
                    VALUES (%s, 'INTRUSION_ALERT', %s)
                """, (mac, f"New MAC found on IP {ip}, which belongs to {ip_owner[0]}"))
                intrusion_count += 1
                print(f"❌ INTRUSION: {mac} is using IP {ip} (belongs to {ip_owner[0]})")
            else:
                # INSERT with OS included
                cursor.execute("""
                    INSERT INTO authorized_devices (mac_address, expected_ip, hostname, os, status, last_seen)
                    VALUES (%s, %s, %s, %s, 'Rogue', NOW())
                """, (mac, ip, hostname, os_guess))
                new_device_count += 1
                print(f"🆕 NEW DEVICE: {mac} added to inventory on {ip}")
                
    conn.commit()
    print(f"\nSummary: {new_device_count} new devices, {intrusion_count} intrusions detected.\n")


# --- FUNCTION 4: CHECK CVEs USING NIST API ---
def check_cves(conn, devices):
    print("Checking services against NIST CVE database...")
    cursor = conn.cursor()

    for device in devices:
        mac = device['mac']
        if 'services' not in device or not device['services']:
            continue
            
        for svc in device['services']:
            service_name = svc['service']
            version = svc['version']
            cache_key = f"{service_name}:{version}"
            
            # 1. Check the local cache first
            cursor.execute("""
                SELECT json_response FROM cve_cache 
                WHERE service_version = %s AND fetched_at > NOW() - INTERVAL 1 DAY
            """, (cache_key,))
            result = cursor.fetchone()
            
            if result:
                cve_data = json.loads(result[0])
                print(f"    [CACHE HIT] {cache_key}")
            else:
                print(f"    [API CALL] Checking {cache_key}...")
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service_name}+{version}"
                try:
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        cve_data = response.json()
                        cursor.execute("""
                            INSERT INTO cve_cache (service_version, json_response) 
                            VALUES (%s, %s)
                        """, (cache_key, json.dumps(cve_data)))
                        print(f"        -> Cached successfully.")
                    else:
                        print(f"        -> API Error: {response.status_code}")
                        continue
                except Exception as e:
                    print(f"        -> Request failed: {e}")
                    continue

            # 2. Parse CVE JSON and save to device_cve_history
            if 'vulnerabilities' in cve_data and cve_data['vulnerabilities']:
                for vuln in cve_data['vulnerabilities']:
                    cve_id = vuln['cve']['id']
                    try:
                        cvss = vuln['cve']['metrics']['cvssMetricV3'][0]['cvssData']['baseScore']
                    except:
                        cvss = 0.0
                    
                    cursor.execute("""
                        SELECT id, status FROM device_cve_history 
                        WHERE mac_address = %s AND cve_id = %s
                    """, (mac, cve_id))
                    existing = cursor.fetchone()
                    
                    if existing:
                        if existing[1] == 'Open':
                            cursor.execute("""
                                UPDATE device_cve_history SET last_seen_at = NOW() 
                                WHERE mac_address = %s AND cve_id = %s
                            """, (mac, cve_id))
                    else:
                        cursor.execute("""
                            INSERT INTO device_cve_history 
                            (mac_address, cve_id, service_name, version_affected, cvss_score, status)
                            VALUES (%s, %s, %s, %s, %s, 'Open')
                        """, (mac, cve_id, service_name, version, cvss))
                        print(f"        ⚠️ New Vulnerability Found: {cve_id} (Score: {cvss}) on {mac}")
                        
    conn.commit()
    print("CVE check complete.\n")


# --- MAIN EXECUTION BLOCK ---
if __name__ == "__main__":
    print("--- STEP 1: CONNECTING TO DATABASE ---")
    db_connection = connect_db()
    
    print("\n--- STEP 2: SCANNING NETWORK ---")
    found_devices = scan_network()
    
    print("\n--- STEP 3: RECONCILING INVENTORY ---")
    reconcile_inventory(db_connection, found_devices)

    print("\n--- STEP 3.5: CHECKING CVEs ---")
    check_cves(db_connection, found_devices)
    
    print("\n--- STEP 4: FINISHING ---")
    db_connection.close()
    print("Database connection closed. Tool finished successfully.")