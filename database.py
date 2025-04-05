import sqlite3
import json
import os
import datetime
from pathlib import Path

class ScanDatabase:
    def __init__(self, db_path="scan_history.db"):
        """Initialize the database connection."""
        # Create the database directory if it doesn't exist
        db_dir = Path("data")
        db_dir.mkdir(exist_ok=True)
        
        self.db_path = os.path.join(db_dir, db_path)
        self.conn = None
        self.cursor = None
        self.connect()
        self.create_tables()
    
    def connect(self):
        """Connect to the SQLite database."""
        self.conn = sqlite3.connect(self.db_path)
        # Enable foreign keys
        self.conn.execute("PRAGMA foreign_keys = ON")
        # Return rows as dictionaries
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
    
    def create_tables(self):
        """Create the necessary tables if they don't exist."""
        # Main scans table to track all scan types
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            description TEXT,
            metadata TEXT
        )
        ''')
        
        # Port scan results
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS port_scan_results (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            banner TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        ''')
        
        # Device discovery results
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_discovery_results (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            mac_address TEXT,
            hostname TEXT,
            device_type TEXT,
            vendor TEXT,
            response_time REAL,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        ''')
        
        # DNS lookup results
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_lookup_results (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            query TEXT NOT NULL,
            record_type TEXT NOT NULL,
            result TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        ''')
        
        # Vulnerability scan results
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_scan_results (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            vulnerability TEXT NOT NULL,
            severity TEXT,
            description TEXT,
            recommendation TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        ''')
        
        # Traceroute results
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS traceroute_results (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            hop_number INTEGER NOT NULL,
            ip_address TEXT,
            hostname TEXT,
            response_time REAL,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        ''')
        
        # SSL certificate results
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssl_certificate_results (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            hostname TEXT NOT NULL,
            issued_to TEXT,
            issued_by TEXT,
            valid_from TEXT,
            valid_until TEXT,
            is_valid BOOLEAN,
            issues TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        ''')
        
        # Geolocation results
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS geolocation_results (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            country TEXT,
            region TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL,
            isp TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        ''')
        
        self.conn.commit()
    
    def add_scan(self, scan_type, target, description=None, metadata=None):
        """Add a new scan to the database and return its ID."""
        timestamp = datetime.datetime.now().isoformat()
        metadata_json = json.dumps(metadata) if metadata else None
        
        self.cursor.execute('''
        INSERT INTO scans (scan_type, target, timestamp, description, metadata)
        VALUES (?, ?, ?, ?, ?)
        ''', (scan_type, target, timestamp, description, metadata_json))
        
        self.conn.commit()
        return self.cursor.lastrowid
    
    def add_port_scan_result(self, scan_id, port, protocol, state, service=None, banner=None):
        """Add a port scan result to the database."""
        self.cursor.execute('''
        INSERT INTO port_scan_results (scan_id, port, protocol, state, service, banner)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (scan_id, port, protocol, state, service, banner))
        
        self.conn.commit()
    
    def add_device_discovery_result(self, scan_id, ip_address, mac_address=None, hostname=None, 
                                   device_type=None, vendor=None, response_time=None):
        """Add a device discovery result to the database."""
        self.cursor.execute('''
        INSERT INTO device_discovery_results 
        (scan_id, ip_address, mac_address, hostname, device_type, vendor, response_time)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, ip_address, mac_address, hostname, device_type, vendor, response_time))
        
        self.conn.commit()
    
    def add_dns_lookup_result(self, scan_id, query, record_type, result):
        """Add a DNS lookup result to the database."""
        self.cursor.execute('''
        INSERT INTO dns_lookup_results (scan_id, query, record_type, result)
        VALUES (?, ?, ?, ?)
        ''', (scan_id, query, record_type, result))
        
        self.conn.commit()
    
    def add_vulnerability_scan_result(self, scan_id, target, vulnerability, severity=None, 
                                     description=None, recommendation=None):
        """Add a vulnerability scan result to the database."""
        self.cursor.execute('''
        INSERT INTO vulnerability_scan_results 
        (scan_id, target, vulnerability, severity, description, recommendation)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (scan_id, target, vulnerability, severity, description, recommendation))
        
        self.conn.commit()
    
    def add_traceroute_result(self, scan_id, hop_number, ip_address=None, hostname=None, response_time=None):
        """Add a traceroute result to the database."""
        self.cursor.execute('''
        INSERT INTO traceroute_results (scan_id, hop_number, ip_address, hostname, response_time)
        VALUES (?, ?, ?, ?, ?)
        ''', (scan_id, hop_number, ip_address, hostname, response_time))
        
        self.conn.commit()
    
    def add_ssl_certificate_result(self, scan_id, hostname, issued_to=None, issued_by=None,
                                  valid_from=None, valid_until=None, is_valid=None, issues=None):
        """Add an SSL certificate result to the database."""
        issues_json = json.dumps(issues) if issues else None
        
        self.cursor.execute('''
        INSERT INTO ssl_certificate_results 
        (scan_id, hostname, issued_to, issued_by, valid_from, valid_until, is_valid, issues)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, hostname, issued_to, issued_by, valid_from, valid_until, is_valid, issues_json))
        
        self.conn.commit()
    
    def add_geolocation_result(self, scan_id, ip_address, country=None, region=None, city=None,
                              latitude=None, longitude=None, isp=None):
        """Add a geolocation result to the database."""
        self.cursor.execute('''
        INSERT INTO geolocation_results 
        (scan_id, ip_address, country, region, city, latitude, longitude, isp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, ip_address, country, region, city, latitude, longitude, isp))
        
        self.conn.commit()
    
    def get_all_scans(self, scan_type=None, limit=50):
        """Get all scans, optionally filtered by type."""
        if scan_type:
            self.cursor.execute('''
            SELECT * FROM scans WHERE scan_type = ? ORDER BY timestamp DESC LIMIT ?
            ''', (scan_type, limit))
        else:
            self.cursor.execute('''
            SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_scan_by_id(self, scan_id):
        """Get a scan by its ID."""
        self.cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        result = self.cursor.fetchone()
        return dict(result) if result else None
    
    def get_port_scan_results(self, scan_id):
        """Get port scan results for a specific scan."""
        self.cursor.execute('''
        SELECT * FROM port_scan_results WHERE scan_id = ? ORDER BY port
        ''', (scan_id,))
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_device_discovery_results(self, scan_id):
        """Get device discovery results for a specific scan."""
        self.cursor.execute('''
        SELECT * FROM device_discovery_results WHERE scan_id = ? ORDER BY ip_address
        ''', (scan_id,))
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_dns_lookup_results(self, scan_id):
        """Get DNS lookup results for a specific scan."""
        self.cursor.execute('''
        SELECT * FROM dns_lookup_results WHERE scan_id = ?
        ''', (scan_id,))
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_vulnerability_scan_results(self, scan_id):
        """Get vulnerability scan results for a specific scan."""
        self.cursor.execute('''
        SELECT * FROM vulnerability_scan_results WHERE scan_id = ?
        ''', (scan_id,))
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_traceroute_results(self, scan_id):
        """Get traceroute results for a specific scan."""
        self.cursor.execute('''
        SELECT * FROM traceroute_results WHERE scan_id = ? ORDER BY hop_number
        ''', (scan_id,))
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_ssl_certificate_results(self, scan_id):
        """Get SSL certificate results for a specific scan."""
        self.cursor.execute('''
        SELECT * FROM ssl_certificate_results WHERE scan_id = ?
        ''', (scan_id,))
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_geolocation_results(self, scan_id):
        """Get geolocation results for a specific scan."""
        self.cursor.execute('''
        SELECT * FROM geolocation_results WHERE scan_id = ?
        ''', (scan_id,))
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def delete_scan(self, scan_id):
        """Delete a scan and all its associated results."""
        self.cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    def compare_port_scans(self, scan_id1, scan_id2):
        """Compare two port scans and return the differences."""
        # Get results for both scans
        results1 = {(r['port'], r['protocol']): r for r in self.get_port_scan_results(scan_id1)}
        results2 = {(r['port'], r['protocol']): r for r in self.get_port_scan_results(scan_id2)}
        
        # Find ports in scan1 but not in scan2
        only_in_scan1 = [k for k in results1.keys() if k not in results2]
        
        # Find ports in scan2 but not in scan1
        only_in_scan2 = [k for k in results2.keys() if k not in results1]
        
        # Find ports with different states
        different_state = [k for k in results1.keys() if k in results2 and results1[k]['state'] != results2[k]['state']]
        
        return {
            'only_in_scan1': [{'port': p[0], 'protocol': p[1], 'state': results1[p]['state']} for p in only_in_scan1],
            'only_in_scan2': [{'port': p[0], 'protocol': p[1], 'state': results2[p]['state']} for p in only_in_scan2],
            'different_state': [{'port': p[0], 'protocol': p[1], 'state1': results1[p]['state'], 'state2': results2[p]['state']} for p in different_state]
        }
    
    def compare_device_discovery(self, scan_id1, scan_id2):
        """Compare two device discovery scans and return the differences."""
        # Get results for both scans
        results1 = {r['ip_address']: r for r in self.get_device_discovery_results(scan_id1)}
        results2 = {r['ip_address']: r for r in self.get_device_discovery_results(scan_id2)}
        
        # Find devices in scan1 but not in scan2
        only_in_scan1 = [ip for ip in results1.keys() if ip not in results2]
        
        # Find devices in scan2 but not in scan1
        only_in_scan2 = [ip for ip in results2.keys() if ip not in results1]
        
        # Find devices with different properties
        different_properties = []
        for ip in results1.keys():
            if ip in results2:
                differences = {}
                for key in ['mac_address', 'hostname', 'device_type', 'vendor']:
                    if results1[ip][key] != results2[ip][key]:
                        differences[key] = {'old': results1[ip][key], 'new': results2[ip][key]}
                
                if differences:
                    different_properties.append({'ip_address': ip, 'differences': differences})
        
        return {
            'only_in_scan1': [results1[ip] for ip in only_in_scan1],
            'only_in_scan2': [results2[ip] for ip in only_in_scan2],
            'different_properties': different_properties
        }
