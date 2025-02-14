import requests
import socket

def get_reverse_dns(ip_address):
    """
    Perform a basic reverse DNS lookup to find the primary hostname for an IP.
    """
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return None

def get_shared_domains(ip_address, api_key=None):
    """
    Use the ViewDNS.info API to find domains sharing the same IP address.
    """
    if not api_key:
        print("API key is required for ViewDNS.info. Visit https://viewdns.info/api/ to get one.")
        return []
    
    url = f"https://api.viewdns.info/reverseip/"
    params = {
        "host": ip_address,
        "apikey": api_key,
        "output": "json"
    }
    
    try:
        response = requests.get(url, params=params)
        data = response.json()
        
        if data.get("response", {}).get("domain_count", 0) > 0:
            domains = [domain["name"] for domain in data["response"]["domains"]]
            return domains
        else:
            return []
    except Exception as e:
        print(f"Error fetching shared domains: {e}")
        return []

if __name__ == "__main__":
    # Replace with your ViewDNS.info API key
    API_KEY = "your_viewdns_api_key_here"
    
    # Input IP address
    ip_address = input("Enter the IP address: ").strip()
    
    # Perform basic reverse DNS lookup
    primary_hostname = get_reverse_dns(ip_address)
    if primary_hostname:
        print(f"\nPrimary Hostname: {primary_hostname}")
    else:
        print("\nNo primary hostname found for this IP.")
    
    # Fetch shared domains using ViewDNS.info API
    shared_domains = get_shared_domains(ip_address, API_KEY)
    if shared_domains:
        print("\nDomains sharing the same IP:")
        for domain in shared_domains:
            print(domain)
    else:
        print("\nNo shared domains found or API key is missing.")