import requests
import socket
from colorama import Fore, Style
from scapy.all import ARP, Ether, srp
import pyfiglet

# ----------------------------
# Core Functions
# ----------------------------

def get_private_ip():
    """Get the host machine's private IP address."""
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception as e:
        return "Unable to determine private IP."

def get_public_ip():
    """Get the host machine's public IP address."""
    try:
        response = requests.get("https://api.ipify.org?format=json")
        return response.json()["ip"]
    except:
        return "Unable to determine public IP."

def validate_ip(ip):
    """Check if the input is a valid IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def get_ip_geolocation(ip_address):
    """Fetch geolocation data using ip-api.com."""
    url = f"http://ip-api.com/json/{ip_address}"
    response = requests.get(url)
    data = response.json()

    if data['status'] == 'success':
        print("\nIP Geolocation Information:")
        print(f"IP Address: {data['query']}")
        print(f"Country: {data['country']}")
        print(f"Region: {data['regionName']}")
        print(f"City: {data['city']}")
        print(f"ZIP Code: {data['zip']}")
        print(f"Latitude: {data['lat']}")
        print(f"Longitude: {data['lon']}")
        print(f"ISP: {data['isp']}")
        print(f"Organization: {data['org']}")
    else:
        print("Failed to retrieve geolocation information.")

def reverse_ip_domain_check(ip_address):
    """Perform reverse DNS lookup."""
    try:
        domain = socket.gethostbyaddr(ip_address)[0]
        print(f"\n[+] Reverse DNS: {domain}")
    except socket.herror:
        print(f"[!] No domain found for {ip_address}")

def get_shared_domains(ip_address, api_key):
    """Find domains sharing the same IP using ViewDNS.info API."""
    url = "https://api.viewdns.info/reverseip/"
    params = {"host": ip_address, "apikey": api_key, "output": "json"}
    
    try:
        response = requests.get(url, params=params)
        data = response.json()
        if data.get("response", {}).get("domains"):
            print("\n[+] Domains on this IP:")
            for domain in data["response"]["domains"]:
                print(f"- {domain['name']}")
        else:
            print("[!] No shared domains found.")
    except:
        print("[!] API error. Check your key or network.")

def scan_network(ip_range):
    """
    Scan the network for connected devices.
    :param ip_range: The IP range to scan (e.g., '192.168.1.1/24')
    :return: A list of devices with their IP, MAC, vendor, and hostname.
    """
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    # Send the packet and receive the response
    result = srp(packet, timeout=2, verbose=0)[0]

    # Parse the response
    devices = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        vendor = get_mac_vendor(mac)
        hostname = get_hostname(ip)
        devices.append({'ip': ip, 'mac': mac, 'vendor': vendor, 'hostname': hostname})

    return devices

def get_mac_vendor(mac):
    """
    Get the vendor name from the MAC address using the MAC Vendor Lookup API.
    :param mac: The MAC address (e.g., '00:11:22:33:44:55')
    :return: The vendor name or 'Unknown'.
    """
    try:
        # Use the MAC Vendor Lookup API
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.text.strip()
    except:
        pass
    return "Unknown"

def get_hostname(ip):
    """
    Resolve the hostname from the IP address.
    :param ip: The IP address (e.g., '192.168.1.1')
    :return: The hostname or 'Unknown'.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return "Unknown"

def display_devices(devices):
    """
    Display the list of devices.
    :param devices: A list of devices with IP, MAC, vendor, and hostname.
    """
    print("\nConnected Devices:")
    print("=" * 90)
    print("IP Address\t\tMAC Address\t\tVendor\t\t\tHostname")
    print("=" * 90)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}\t{device['vendor']}\t\t{device['hostname']}")

# ----------------------------
# Menu System
# ----------------------------

def show_banner():
    banner_text = f"""
    {Fore.GREEN}███╗   ██╗███████╗████████╗████████╗ ██████╗  ██████╗ ██╗     
    ████╗  ██║██╔════╝╚══██╔══╝╚══██╔══╝██╔═══██╗██╔═══██╗██║     
    ██╔██╗ ██║█████╗     ██║      ██║   ██║   ██║██║   ██║██║     
    ██║╚██╗██║██╔══╝     ██║      ██║   ██║   ██║██║   ██║██║     
    ██║ ╚████║███████╗   ██║      ██║   ╚██████╔╝╚██████╔╝███████╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝{Style.RESET_ALL}
    """
    print(banner_text)

def main_menu():
    show_banner()
    while True:
        print("\nOptions:")
        print("1. Check Host IPs (Private/Public)")
        print("2. Scan an IP Address")
        print("3. Scan Local Network (NETSCAN)")
        print("4. Exit")
        
        choice = input("\nSelect an option (1-4): ").strip()
        
        if choice == "1":
            private_ip = get_private_ip()
            public_ip = get_public_ip()
            print(f"\nPrivate IP: {private_ip}")
            print(f"Public IP: {public_ip}")
            
            print("\nPerform action on these IPs?")
            print("1. Geolocation")
            print("2. Reverse DNS")
            print("3. None")
            
            action = input("\nChoose an action (1-3): ").strip()
            
            if action == "1":
                get_ip_geolocation(public_ip)
            elif action == "2":
                reverse_ip_domain_check(public_ip)
            elif action == "3":
                continue
            else:
                print("[!] Invalid choice")
                
        elif choice == "2":
            ip = input("Enter IP address: ").strip()
            if not validate_ip(ip):
                print("[!] Invalid IP address")
                continue
                
            print("\nScan Options:")
            print("1. Geolocation")
            print("2. Reverse DNS")
            print("3. Shared Domains (requires API key)")
            
            scan_choice = input("\nChoose scan type (1-3): ").strip()
            
            if scan_choice == "1":
                get_ip_geolocation(ip)
            elif scan_choice == "2":
                reverse_ip_domain_check(ip)
            elif scan_choice == "3":
                api_key = input("Enter ViewDNS API key: ").strip()
                get_shared_domains(ip, api_key)
            else:
                print("[!] Invalid choice")
                
        elif choice == "3":
            ip_range = input("Enter IP range to scan (e.g., 192.168.1.1/24): ").strip()
            print(f"\nScanning network {ip_range}...")
            devices = scan_network(ip_range)
            display_devices(devices)
                
        elif choice == "4":
            print("Exiting...")
            break
            
        else:
            print("[!] Invalid choice")

if __name__ == "__main__":
    main_menu()
