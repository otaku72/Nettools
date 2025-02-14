import requests
import socket

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

# ----------------------------
# Menu System
# ----------------------------

def show_banner():
    print("""
    ███╗   ██╗███████╗████████╗████████╗ ██████╗  ██████╗ ██╗     
    ████╗  ██║██╔════╝╚══██╔══╝╚══██╔══╝██╔═══██╗██╔═══██╗██║     
    ██╔██╗ ██║█████╗     ██║      ██║   ██║   ██║██║   ██║██║     
    ██║╚██╗██║██╔══╝     ██║      ██║   ██║   ██║██║   ██║██║     
    ██║ ╚████║███████╗   ██║      ██║   ╚██████╔╝╚██████╔╝███████╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
    """)

def main_menu():
    show_banner()
    while True:
        print("\nOptions:")
        print("1. Check Host IPs (Private/Public)")
        print("2. Scan an IP Address")
        print("3. Exit")
        
        choice = input("\nSelect an option (1-3): ").strip()
        
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
            print("Exiting...")
            break
            
        else:
            print("[!] Invalid choice")

if __name__ == "__main__":
    main_menu()
