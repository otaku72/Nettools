import requests
import socket

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
    ip_address = input("Enter the IP address: ")
    
    # Get IP Geolocation
    get_ip_geolocation(ip_address)
    
    # Perform Reverse IP Domain Check
    reverse_ip_domain_check(ip_address)