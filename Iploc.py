import requests
import socket

def get_private_ip():
    """
    Get the private IP address of the host machine (local network).
    """
    try:
        # Get the hostname of the machine
        hostname = socket.gethostname()
        # Get the IP address associated with the hostname
        private_ip = socket.gethostbyname(hostname)
        return private_ip
    except Exception as e:
        return "Unable to determine private IP."

def get_public_ip():
    """
    Get the public IP address of the host machine (external internet-facing IP).
    """
    try:
        # Use an external service to fetch the public IP
        response = requests.get("https://api.ipify.org?format=json")
        data = response.json()
        return data["ip"]
    except Exception as e:
        return "Unable to determine public IP."

def get_ip_geolocation(ip_address):
    """
    Get geolocation information for a given IP address using the ip-api.com service.
    """
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
    """
    Perform a reverse IP domain check to find associated domain names.
    """
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        print(f"\nReverse IP Domain Check: {domain_name}")
    except socket.herror:
        print(f"\nNo domain name found for IP: {ip_address}")

if __name__ == "__main__":
    # Get the private and public IP addresses of the host machine
    private_ip = get_private_ip()
    public_ip = get_public_ip()
    
    print(f"Host Private IP: {private_ip}")
    print(f"Host Public IP: {public_ip}")
    
    # Ask the user which IP to use (private or public)
    ip_type = input("Do you want to use the private IP or public IP? (private/public): ").strip().lower()
    
    if ip_type == "private":
        ip_address = private_ip
    elif ip_type == "public":
        ip_address = public_ip
    else:
        print("Invalid choice. Using public IP by default.")
        ip_address = public_ip
    
    print(f"\nUsing IP: {ip_address}")
    
    # Get IP Geolocation
    get_ip_geolocation(ip_address)
    
    # Perform Reverse IP Domain Check
    reverse_ip_domain_check(ip_address)