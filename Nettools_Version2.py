Jimimport argparse
import socket
import requests
from scapy.all import ARP, Ether, srp
import psutil
import ipaddress
from colorama import Fore, Style, init
import sys
import time

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

def port_scan(ip, ports="1-1024"):
    open_ports = []
    try:
        if '-' in ports:
            start, end = map(int, ports.split('-'))
            port_range = range(start, end+1)
        else:
            port_range = [int(ports)]
    except:
        print(f"{Fore.RED}Invalid port range.")
        return
    print(f"{Fore.YELLOW}Scanning {ip} ports {ports} ...")
    for port in port_range:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"{Fore.GREEN}Port {port} is open")
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

    parser_portscan = subparsers.add_parser("port-scan", help="Scan ports on a host")
    parser_portscan.add_argument("ip", help="Target IP address")
    parser_portscan.add_argument("--ports", default="1-1024", help="Port or port range (default 1-1024)")

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
        port_scan(args.ip, args.ports)
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