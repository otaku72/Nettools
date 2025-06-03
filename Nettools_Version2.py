import argparse
import socket
import requests
from scapy.all import ARP, Ether, srp
import psutil
import ipaddress
from colorama import Fore, Style, init
import sys
import time
import concurrent.futures
from typing import List, Dict

init(autoreset=True)

def get_private_ip():
    try:
        interfaces = psutil.net_if_addrs()
        for interface_name, interface_addresses in interfaces.items():
            for address in interface_addresses:
                if address.family == socket.AF_INET:
                    print(f"{Fore.GREEN}Interface: {interface_name}, IP Address: {address.address}")
        return True
    except Exception as e:
        print(f"{Fore.RED}Unable to determine private IP: {e}")
        return False

def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        print(f"{Fore.GREEN}Public IP: {response.json()['ip']}")
        return True
    except Exception as e:
        print(f"{Fore.RED}Unable to determine public IP: {e}")
        return False

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        print(f"{Fore.GREEN}Valid IP address: {ip}")
        return True
    except socket.error:
        print(f"{Fore.RED}Invalid IP address: {ip}")
        return False

def get_ip_geolocation(ip_address):
    url = f"http://ip-api.com/json/{ip_address}"
    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        if data['status'] == 'success':
            print(f"{Fore.BLUE}IP Geolocation for {ip_address}:")
            for key in ['country', 'regionName', 'city', 'zip', 'lat', 'lon', 'isp', 'org']:
                print(f"  {key.capitalize()}: {data.get(key, 'N/A')}")
        else:
            print(f"{Fore.RED}Failed to retrieve geolocation information.")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")

def reverse_ip_domain_check(ip_address):
    try:
        domain = socket.gethostbyaddr(ip_address)[0]
        print(f"{Fore.GREEN}Reverse DNS: {domain}")
    except socket.herror:
        print(f"{Fore.RED}No domain found for {ip_address}")

def get_service_banner(ip: str, port: int) -> str:
    """Attempt to grab service banner from open port"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            s.send(b'GET / HTTP/1.1\r\n\r\n')
            return s.recv(1024).decode(errors='ignore').strip()
    except:
        return "No banner retrieved"

def check_vulnerabilities(service: str, version: str) -> List[str]:
    """Check for known vulnerabilities (simplified example)"""
    vulns = []
    service = service.lower()
    
    # Example vulnerability checks
    if "ssh" in service and "7.2" in version:
        vulns.append("CVE-2017-0144: OpenSSH 7.2 vulnerability")
    if "http" in service and "Apache 2.4.49" in version:
        vulns.append("CVE-2021-41773: Apache Path Traversal")
    if "ftp" in service and "vsftpd 2.3.4" in version:
        vulns.append("CVE-2011-2523: vsftpd backdoor")
    
    return vulns

def scan_port(ip: str, port: int) -> Dict:
    """Scan individual port with security assessment"""
    result = {
        'port': port,
        'open': False,
        'service': 'unknown',
        'banner': '',
        'vulnerabilities': []
    }
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                result['open'] = True
                banner = get_service_banner(ip, port)
                result['banner'] = banner
                
                # Simple service detection
                if port == 80 or port == 443:
                    result['service'] = 'HTTP'
                elif port == 22:
                    result['service'] = 'SSH'
                elif port == 21:
                    result['service'] = 'FTP'
                elif port == 3389:
                    result['service'] = 'RDP'
                
                # Vulnerability check
                result['vulnerabilities'] = check_vulnerabilities(result['service'], banner)
                
        return result
    except Exception as e:
        print(f"{Fore.RED}Error scanning port {port}: {e}")
        return result

def port_scan(ip: str, ports: str = "1-1024", threads: int = 100) -> None:
    """Enhanced port scanner with security features"""
    try:
        if '-' in ports:
            start, end = map(int, ports.split('-'))
            port_range = range(start, end + 1)
        else:
            port_range = [int(ports)]
    except:
        print(f"{Fore.RED}Invalid port range.")
        return

    print(f"{Fore.YELLOW}\n[+] Scanning {ip} ports {ports} with security assessment...")
    print(f"{Fore.CYAN}[*] Using {threads} threads for faster scanning\n")
    
    open_ports = []
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in port_range}
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result['open']:
                open_ports.append(result)
                status = f"{Fore.GREEN}OPEN"
                print(f"{status} {result['port']}/tcp - {result['service']}")
                print(f"   Banner: {result['banner'][:100]}...")
                
                if result['vulnerabilities']:
                    print(f"{Fore.RED}   [!] Vulnerabilities detected:")
                    for vuln in result['vulnerabilities']:
                        print(f"       - {vuln}")
                print()
    
    duration = time.time() - start_time
    print(f"\n{Fore.CYAN}[*] Scan completed in {duration:.2f} seconds")
    print(f"{Fore.CYAN}[*] Found {len(open_ports)} open ports")
    
    if not open_ports:
        print(f"{Fore.YELLOW}No open ports found in range.")

def banner_grab(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((ip, int(port)))
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(1024)
            print(f"{Fore.GREEN}Banner for {ip}:{port}:")
            print(banner.decode(errors='replace'))
    except Exception as e:
        print(f"{Fore.RED}Failed to grab banner: {e}")

def scan_network(ip_range):
    print(f"{Fore.YELLOW}Scanning network: {ip_range}")
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            print(f"{Fore.GREEN}IP: {received.psrc}, MAC: {received.hwsrc}")
    except Exception as e:
        print(f"{Fore.RED}Scan failed: {e}")

def whois_lookup(domain):
    try:
        import whois
        data = whois.whois(domain)
        print(f"{Fore.BLUE}Whois info for {domain}:")
        print(data)
    except ImportError:
        print(f"{Fore.RED}whois module not installed. Install with 'pip install python-whois'")
    except Exception as e:
        print(f"{Fore.RED}Whois lookup failed: {e}")

def dns_lookup(domain):
    try:
        import dns.resolver
        result = dns.resolver.resolve(domain, 'A')
        print(f"{Fore.GREEN}A records for {domain}:")
        for ipval in result:
            print(f"  {ipval.to_text()}")
    except ImportError:
        print(f"{Fore.RED}dnspython module not installed. Install with 'pip install dnspython'")
    except Exception as e:
        print(f"{Fore.RED}DNS lookup failed: {e}")

def cli_menu():
    parser = argparse.ArgumentParser(description="Nettools - Advanced Networking and Cybersecurity Toolkit")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("private-ip", help="Get all private IP addresses")
    subparsers.add_parser("public-ip", help="Get public IP address")

    parser_validate = subparsers.add_parser("validate-ip", help="Validate an IP address")
    parser_validate.add_argument("ip", help="IP address to validate")

    parser_geo = subparsers.add_parser("geoip", help="Geolocate an IP address")
    parser_geo.add_argument("ip", help="IP address to geolocate")

    parser_reverse = subparsers.add_parser("reverse-dns", help="Reverse DNS lookup")
    parser_reverse.add_argument("ip", help="IP address for reverse lookup")

    parser_portscan = subparsers.add_parser("port-scan", help="Advanced port scan with security assessment")
    parser_portscan.add_argument("ip", help="Target IP address")
    parser_portscan.add_argument("--ports", default="1-1024", help="Port or port range (default 1-1024)")
    parser_portscan.add_argument("--threads", type=int, default=100, 
                               help="Number of threads (default 100)")

    parser_banner = subparsers.add_parser("banner-grab", help="Grab service banner")
    parser_banner.add_argument("ip", help="Target IP address")
    parser_banner.add_argument("port", help="Target port")

    parser_netscan = subparsers.add_parser("netscan", help="Scan local network for devices")
    parser_netscan.add_argument("range", help="CIDR or IP range (e.g. 192.168.1.1/24)")

    parser_whois = subparsers.add_parser("whois", help="Whois lookup")
    parser_whois.add_argument("domain", help="Domain name")

    parser_dns = subparsers.add_parser("dns", help="DNS lookup (A record)")
    parser_dns.add_argument("domain", help="Domain name")

    args = parser.parse_args()

    if args.command == "private-ip":
        get_private_ip()
    elif args.command == "public-ip":
        get_public_ip()
    elif args.command == "validate-ip":
        validate_ip(args.ip)
    elif args.command == "geoip":
        get_ip_geolocation(args.ip)
    elif args.command == "reverse-dns":
        reverse_ip_domain_check(args.ip)
    elif args.command == "port-scan":
        port_scan(args.ip, args.ports, args.threads)
    elif args.command == "banner-grab":
        banner_grab(args.ip, args.port)
    elif args.command == "netscan":
        scan_network(args.range)
    elif args.command == "whois":
        whois_lookup(args.domain)
    elif args.command == "dns":
        dns_lookup(args.domain)
    else:
        parser.print_help()

if __name__ == "__main__":
    cli_menu()
