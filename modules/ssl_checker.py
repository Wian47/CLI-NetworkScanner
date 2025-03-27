import ssl
import socket
import datetime
import OpenSSL
from typing import Dict, List, Optional, Tuple, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
import concurrent.futures
import re
import ipaddress

class SSLCertificateChecker:
    """SSL/TLS Certificate checking module for NetworkScan Pro."""
    
    def __init__(self, console: Console = None):
        """Initialize the SSL Certificate Checker."""
        self.console = console or Console()
        
    def get_certificate(self, hostname: str, port: int = 443, timeout: int = 10) -> Dict:
        """
        Fetch SSL certificate from a host.
        
        Args:
            hostname: Target hostname or IP
            port: Target port (default 443)
            timeout: Connection timeout in seconds
            
        Returns:
            Dictionary with certificate details or error
        """
        try:
            # Create connection
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                    # Get certificate in DER format
                    der_cert = ssl_sock.getpeercert(True)
                    # Convert to PEM format for OpenSSL
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)
                    
                    # Get SSL/TLS version
                    ssl_version = ssl_sock.version()
                    
                    # Get cipher information
                    cipher = ssl_sock.cipher()
                    
                    # Get certificate chain (simplified - we can't easily get the entire chain)
                    # In a production app, you'd use a different approach to get the full chain
                    chain_length = 1
                    
                    # Extract and format important details
                    cert_data = {
                        'subject': dict(x509.get_subject().get_components()),
                        'issuer': dict(x509.get_issuer().get_components()),
                        'version': x509.get_version(),
                        'serialNumber': x509.get_serial_number(),
                        'notBefore': datetime.datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'),
                        'notAfter': datetime.datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'),
                        'subjectAltName': self._get_alt_names(x509),
                        'OCSP': self._get_ocsp_uri(x509),
                        'caIssuers': self._get_ca_issuers(x509),
                        'crlDistributionPoints': self._get_crl_distribution_points(x509),
                        'keyUsage': self._get_key_usage(x509),
                        'extendedKeyUsage': self._get_extended_key_usage(x509),
                        'signatureAlgorithm': x509.get_signature_algorithm().decode('ascii'),
                        'fingerprint': x509.digest('sha256').decode('ascii'),
                        'publicKeyBits': x509.get_pubkey().bits(),
                        'publicKeyType': self._get_public_key_type(x509),
                        'chain_length': chain_length,
                        'ssl_version': ssl_version,
                        'cipher': cipher
                    }
                    
                    return {
                        'success': True,
                        'cert_data': cert_data,
                        'raw_cert': x509
                    }
                    
        except (socket.gaierror, socket.error) as e:
            return {
                'success': False,
                'error': f"Connection error: {str(e)}"
            }
        except ssl.SSLError as e:
            return {
                'success': False,
                'error': f"SSL error: {str(e)}"
            }
        except Exception as e:
            return {
                'success': False,
                'error': f"Error: {str(e)}"
            }
    
    def _get_alt_names(self, cert: OpenSSL.crypto.X509) -> List[str]:
        """Extract Subject Alternative Names from certificate."""
        alt_names = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                alt_names_str = str(ext)
                # Parse the alt names string
                for name in alt_names_str.split(', '):
                    if ':' in name:
                        type_val = name.split(':', 1)
                        if len(type_val) == 2:
                            alt_names.append(name)
        return alt_names
    
    def _get_ocsp_uri(self, cert: OpenSSL.crypto.X509) -> Optional[str]:
        """Extract OCSP URI from certificate."""
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'authorityInfoAccess':
                aia_str = str(ext)
                for line in aia_str.split('\n'):
                    if 'OCSP' in line and 'URI:' in line:
                        uri = line.split('URI:', 1)[1].strip()
                        return uri
        return None
    
    def _get_ca_issuers(self, cert: OpenSSL.crypto.X509) -> List[str]:
        """Extract CA Issuers from certificate."""
        issuers = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'authorityInfoAccess':
                aia_str = str(ext)
                for line in aia_str.split('\n'):
                    if 'CA Issuers' in line and 'URI:' in line:
                        uri = line.split('URI:', 1)[1].strip()
                        issuers.append(uri)
        return issuers
    
    def _get_crl_distribution_points(self, cert: OpenSSL.crypto.X509) -> List[str]:
        """Extract CRL Distribution Points from certificate."""
        crls = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'crlDistributionPoints':
                crl_str = str(ext)
                for line in crl_str.split('\n'):
                    if 'URI:' in line:
                        uri = line.split('URI:', 1)[1].strip()
                        crls.append(uri)
        return crls
    
    def _get_key_usage(self, cert: OpenSSL.crypto.X509) -> List[str]:
        """Extract Key Usage from certificate."""
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'keyUsage':
                return str(ext).split(', ')
        return []
    
    def _get_extended_key_usage(self, cert: OpenSSL.crypto.X509) -> List[str]:
        """Extract Extended Key Usage from certificate."""
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'extendedKeyUsage':
                return str(ext).split(', ')
        return []
    
    def _get_public_key_type(self, cert: OpenSSL.crypto.X509) -> str:
        """Determine the public key type."""
        pk_type = cert.get_pubkey().type()
        if pk_type == OpenSSL.crypto.TYPE_RSA:
            return 'RSA'
        elif pk_type == OpenSSL.crypto.TYPE_DSA:
            return 'DSA'
        elif pk_type == OpenSSL.crypto.TYPE_EC:
            return 'EC'
        else:
            return f"Unknown ({pk_type})"
    
    def check_expiration(self, cert_data: Dict) -> Dict:
        """
        Check certificate expiration status.
        
        Args:
            cert_data: Certificate data from get_certificate
            
        Returns:
            Dictionary with expiration status
        """
        if not cert_data.get('success', False):
            return {'valid': False, 'reason': 'Certificate data missing'}
        
        cert = cert_data['cert_data']
        now = datetime.datetime.utcnow()
        not_before = cert['notBefore']
        not_after = cert['notAfter']
        days_to_expiration = (not_after - now).days
        
        # Check if certificate is currently valid
        if now < not_before:
            return {
                'valid': False,
                'reason': 'Certificate not yet valid',
                'not_before': not_before,
                'not_after': not_after,
                'days_to_expiration': days_to_expiration
            }
        elif now > not_after:
            return {
                'valid': False,
                'reason': 'Certificate has expired',
                'not_before': not_before,
                'not_after': not_after,
                'days_to_expiration': days_to_expiration
            }
        else:
            # Warn if certificate is expiring soon
            if days_to_expiration <= 0:
                return {
                    'valid': False,
                    'reason': 'Certificate has expired',
                    'not_before': not_before,
                    'not_after': not_after,
                    'days_to_expiration': days_to_expiration
                }
            elif days_to_expiration <= 30:
                return {
                    'valid': True,
                    'status': 'warning',
                    'reason': f'Certificate expiring soon (in {days_to_expiration} days)',
                    'not_before': not_before,
                    'not_after': not_after,
                    'days_to_expiration': days_to_expiration
                }
            else:
                return {
                    'valid': True,
                    'status': 'ok',
                    'reason': f'Certificate valid for {days_to_expiration} more days',
                    'not_before': not_before,
                    'not_after': not_after,
                    'days_to_expiration': days_to_expiration
                }
    
    def verify_hostname(self, hostname: str, cert_data: Dict) -> Dict:
        """
        Verify if certificate is valid for the given hostname.
        
        Args:
            hostname: Hostname to verify
            cert_data: Certificate data from get_certificate
            
        Returns:
            Dictionary with validation status
        """
        if not cert_data.get('success', False):
            return {'valid': False, 'reason': 'Certificate data missing'}
        
        cert = cert_data['cert_data']
        
        # Get subject CN
        subject_cn = None
        if b'CN' in cert['subject']:
            subject_cn = cert['subject'][b'CN'].decode('utf-8')
        
        # Get all hostnames from SAN
        hostnames = []
        for alt_name in cert['subjectAltName']:
            if alt_name.startswith('DNS:'):
                hostnames.append(alt_name.split(':', 1)[1])
            
        # If no SAN, use CN
        if not hostnames and subject_cn:
            hostnames.append(subject_cn)
        
        # Check if hostname matches
        hostname_matches = False
        matching_hostname = None
        
        # Try to identify if hostname is an IP
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            pass
        
        for cert_hostname in hostnames:
            # Direct match
            if hostname.lower() == cert_hostname.lower():
                hostname_matches = True
                matching_hostname = cert_hostname
                break
            
            # Wildcard match
            if cert_hostname.startswith('*.') and not is_ip:
                domain_parts = hostname.split('.')
                if len(domain_parts) >= 2:
                    wildcard_domain = '.'.join(domain_parts[1:])
                    cert_domain = cert_hostname[2:]  # Remove '*.'
                    if wildcard_domain.lower() == cert_domain.lower():
                        hostname_matches = True
                        matching_hostname = cert_hostname
                        break
        
        if hostname_matches:
            return {
                'valid': True,
                'reason': f'Hostname matches certificate: {matching_hostname}',
                'subject_cn': subject_cn,
                'alternative_names': hostnames
            }
        else:
            return {
                'valid': False,
                'reason': 'Hostname does not match certificate',
                'subject_cn': subject_cn,
                'alternative_names': hostnames
            }
    
    def validate_chain(self, cert_data: Dict) -> Dict:
        """
        Validate the certificate chain.
        
        Args:
            cert_data: Certificate data from get_certificate
            
        Returns:
            Dictionary with chain validation status
        """
        if not cert_data.get('success', False):
            return {'valid': False, 'reason': 'Certificate data missing'}
        
        cert = cert_data['cert_data']
        
        # Check chain length
        chain_length = cert.get('chain_length', 0)
        if chain_length == 0:
            return {'valid': False, 'reason': 'No certificate chain provided'}
        
        # Check if self-signed
        subject = cert['subject']
        issuer = cert['issuer']
        
        is_self_signed = True
        for key in subject:
            if key in issuer and subject[key] != issuer[key]:
                is_self_signed = False
                break
        
        if is_self_signed:
            return {'valid': False, 'reason': 'Certificate is self-signed'}
        
        # Here we would normally do a more complete chain validation
        # using OpenSSL or a similar library. For simplicity, we'll
        # just check if the chain exists and is not self-signed.
        
        return {
            'valid': True,
            'reason': f'Certificate chain appears valid (length: {chain_length})',
            'chain_length': chain_length
        }
    
    def check_certificate(self, hostname: str, port: int = 443) -> Dict:
        """
        Comprehensive certificate check.
        
        Args:
            hostname: Target hostname
            port: Target port (default 443)
            
        Returns:
            Dictionary with all check results
        """
        # Get certificate
        cert_data = self.get_certificate(hostname, port)
        
        if not cert_data.get('success', False):
            return {
                'success': False,
                'error': cert_data.get('error', 'Failed to retrieve certificate')
            }
        
        # Check expiration
        expiration_status = self.check_expiration(cert_data)
        
        # Verify hostname
        hostname_status = self.verify_hostname(hostname, cert_data)
        
        # Validate chain
        chain_status = self.validate_chain(cert_data)
        
        # Check for common SSL/TLS issues
        security_issues = self._check_security_issues(cert_data)
        
        # Overall status
        is_valid = (
            expiration_status.get('valid', False) and
            hostname_status.get('valid', False) and
            chain_status.get('valid', False) and
            len(security_issues) == 0
        )
        
        return {
            'success': True,
            'hostname': hostname,
            'port': port,
            'is_valid': is_valid,
            'cert_data': cert_data['cert_data'],
            'expiration': expiration_status,
            'hostname_validation': hostname_status,
            'chain_validation': chain_status,
            'security_issues': security_issues
        }
    
    def _check_security_issues(self, cert_data: Dict) -> List[Dict]:
        """
        Check for common SSL/TLS security issues.
        
        Args:
            cert_data: Certificate data from get_certificate
            
        Returns:
            List of identified security issues
        """
        issues = []
        
        if not cert_data.get('success', False):
            return [{'level': 'critical', 'issue': 'Unable to check security issues due to certificate retrieval failure'}]
        
        cert = cert_data['cert_data']
        
        # Check signature algorithm (SHA-1 is weak)
        sig_alg = cert['signatureAlgorithm']
        if 'sha1' in sig_alg.lower():
            issues.append({
                'level': 'high',
                'issue': f'Weak signature algorithm: {sig_alg}',
                'description': 'SHA-1 is no longer considered secure for certificate signatures'
            })
        
        # Check key size
        key_bits = cert['publicKeyBits']
        key_type = cert['publicKeyType']
        
        if key_type == 'RSA' and key_bits < 2048:
            issues.append({
                'level': 'high',
                'issue': f'Weak key size: {key_bits} bits ({key_type})',
                'description': 'RSA keys should be at least 2048 bits'
            })
        elif key_type == 'EC' and key_bits < 256:
            issues.append({
                'level': 'high',
                'issue': f'Weak key size: {key_bits} bits ({key_type})',
                'description': 'EC keys should be at least 256 bits'
            })
        
        # Check SSL/TLS version
        ssl_version = cert['ssl_version']
        if ssl_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
            issues.append({
                'level': 'high',
                'issue': f'Outdated protocol: {ssl_version}',
                'description': f'{ssl_version} is no longer considered secure, should use TLSv1.2 or later'
            })
        
        # Check cipher strength
        cipher = cert['cipher']
        if cipher:
            cipher_name = cipher[0]
            if any(x in cipher_name.lower() for x in ['des', 'rc4', 'null', 'export']):
                issues.append({
                    'level': 'high',
                    'issue': f'Weak cipher: {cipher_name}',
                    'description': 'The connection is using a known weak cipher'
                })
            
        return issues
    
    def batch_check(self, targets: List[Tuple[str, int]], max_workers: int = 10) -> Dict[str, Dict]:
        """
        Check certificates for multiple targets in parallel.
        
        Args:
            targets: List of (hostname, port) tuples
            max_workers: Maximum number of parallel workers
            
        Returns:
            Dictionary mapping hostnames to check results
        """
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_host = {
                executor.submit(self.check_certificate, hostname, port): (hostname, port)
                for hostname, port in targets
            }
            
            for future in concurrent.futures.as_completed(future_to_host):
                hostname, port = future_to_host[future]
                try:
                    result = future.result()
                    results[f"{hostname}:{port}"] = result
                except Exception as e:
                    results[f"{hostname}:{port}"] = {
                        'success': False,
                        'error': str(e)
                    }
        
        return results
    
    def display_certificate_info(self, result: Dict) -> None:
        """
        Display certificate information in a nice format.
        
        Args:
            result: Result from check_certificate
        """
        if not result.get('success', False):
            self.console.print(f"[bold red]Error:[/bold red] {result.get('error', 'Unknown error')}")
            return
        
        hostname = result['hostname']
        port = result['port']
        cert_data = result['cert_data']
        
        # Overall status
        status_color = "green" if result['is_valid'] else "red"
        status_text = "Valid" if result['is_valid'] else "Invalid"
        
        self.console.print(Panel(
            f"[bold {status_color}]Certificate Status: {status_text}[/bold {status_color}]",
            title=f"SSL/TLS Certificate for {hostname}:{port}",
            border_style="blue"
        ))
        
        # Basic certificate info
        basic_table = Table(
            title="Certificate Details",
            box=box.ROUNDED,
            border_style="blue",
            header_style="bold cyan",
            padding=(0, 1)
        )
        
        basic_table.add_column("Field", style="cyan")
        basic_table.add_column("Value", style="yellow")
        
        # Extract CN from subject and issuer
        subject_cn = (cert_data['subject'].get(b'CN', b'')).decode('utf-8', errors='replace')
        issuer_cn = (cert_data['issuer'].get(b'CN', b'')).decode('utf-8', errors='replace')
        
        basic_table.add_row("Subject", subject_cn)
        basic_table.add_row("Issuer", issuer_cn)
        basic_table.add_row("Serial Number", str(cert_data['serialNumber']))
        basic_table.add_row("Version", f"v{cert_data['version'] + 1}")
        basic_table.add_row("Signature Algorithm", cert_data['signatureAlgorithm'])
        basic_table.add_row("Public Key", f"{cert_data['publicKeyType']} {cert_data['publicKeyBits']} bits")
        
        # Format dates
        not_before = cert_data['notBefore'].strftime('%Y-%m-%d %H:%M:%S UTC')
        not_after = cert_data['notAfter'].strftime('%Y-%m-%d %H:%M:%S UTC')
        
        basic_table.add_row("Valid From", not_before)
        basic_table.add_row("Valid Until", not_after)
        basic_table.add_row("SSL/TLS Version", cert_data['ssl_version'])
        
        self.console.print(basic_table)
        
        # Subject Alternative Names
        if cert_data['subjectAltName']:
            san_table = Table(
                title="Subject Alternative Names",
                box=box.ROUNDED,
                border_style="blue",
                header_style="bold cyan",
                padding=(0, 1)
            )
            
            san_table.add_column("Type", style="cyan")
            san_table.add_column("Value", style="yellow")
            
            for alt_name in cert_data['subjectAltName']:
                if ':' in alt_name:
                    name_type, value = alt_name.split(':', 1)
                    san_table.add_row(name_type, value)
            
            self.console.print(san_table)
        
        # Validation Results
        validation_table = Table(
            title="Validation Results",
            box=box.ROUNDED,
            border_style="blue",
            header_style="bold cyan",
            padding=(0, 1)
        )
        
        validation_table.add_column("Check", style="cyan")
        validation_table.add_column("Status", style="yellow")
        validation_table.add_column("Details", style="white")
        
        # Expiration status
        expiration = result['expiration']
        exp_status = "✓ Valid" if expiration.get('valid', False) else "✗ Invalid"
        exp_color = "green" if expiration.get('valid', False) else "red"
        if expiration.get('status') == 'warning':
            exp_color = "yellow"
            
        validation_table.add_row(
            "Expiration",
            f"[{exp_color}]{exp_status}[/{exp_color}]",
            expiration.get('reason', 'Unknown')
        )
        
        # Hostname validation
        hostname_val = result['hostname_validation']
        hostname_status = "✓ Valid" if hostname_val.get('valid', False) else "✗ Invalid"
        hostname_color = "green" if hostname_val.get('valid', False) else "red"
        
        validation_table.add_row(
            "Hostname",
            f"[{hostname_color}]{hostname_status}[/{hostname_color}]",
            hostname_val.get('reason', 'Unknown')
        )
        
        # Chain validation
        chain_val = result['chain_validation']
        chain_status = "✓ Valid" if chain_val.get('valid', False) else "✗ Invalid"
        chain_color = "green" if chain_val.get('valid', False) else "red"
        
        validation_table.add_row(
            "Chain",
            f"[{chain_color}]{chain_status}[/{chain_color}]",
            chain_val.get('reason', 'Unknown')
        )
        
        self.console.print(validation_table)
        
        # Security issues
        if result['security_issues']:
            issues_table = Table(
                title="Security Issues",
                box=box.ROUNDED,
                border_style="blue",
                header_style="bold cyan",
                padding=(0, 1)
            )
            
            issues_table.add_column("Severity", style="cyan")
            issues_table.add_column("Issue", style="yellow")
            issues_table.add_column("Description", style="white")
            
            for issue in result['security_issues']:
                severity = issue['level']
                severity_color = "red" if severity == "high" else "yellow"
                
                issues_table.add_row(
                    f"[{severity_color}]{severity.upper()}[/{severity_color}]",
                    issue['issue'],
                    issue.get('description', '')
                )
            
            self.console.print(issues_table)
    
    def check_website(self, url: str, port: Optional[int] = None) -> None:
        """
        Check certificate for a website URL.
        
        Args:
            url: Website URL (with or without protocol)
            port: Optional port number (default: 443)
        """
        # Parse the URL to extract hostname and port
        if '//' not in url and ':' not in url:
            url = f"https://{url}"
            
        # Extract hostname and port
        match = re.search(r'^(?:https?://)?([^:/]+)(?::(\d+))?', url)
        if not match:
            self.console.print(f"[bold red]Error:[/bold red] Invalid URL format: {url}")
            return
            
        hostname = match.group(1)
        port_str = match.group(2)
        
        if port is None:
            if port_str:
                port = int(port_str)
            else:
                # Default to 443 for HTTPS
                port = 443
        
        # Display what we're checking
        self.console.print(f"[bold cyan]Checking SSL/TLS certificate for [yellow]{hostname}:{port}[/yellow][/bold cyan]")
        
        # Run the check
        result = self.check_certificate(hostname, port)
        
        # Display results
        self.display_certificate_info(result) 