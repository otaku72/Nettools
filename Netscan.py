from scapy.all import ARP, Ether, srp
import socket
import requests
import pyfiglet

def display_banner():
    """
    Display the NETSCAN banner using pyfiglet.
    """
    ascii_art = pyfiglet.figlet_format("NETSCAN", font="block")
    print(ascii_art)
    print("=" * 60)
    print("Wi-Fi User Scanner - Scan connected devices on your network")
    print("=" * 60)
    print()

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
    print("\nAll Connected Devices:")
    print("=" * 90)
    print("IP Address\t\tMAC Address\t\tVendor\t\t\tHostname")
    print("=" * 90)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}\t{device['vendor']}\t\t{device['hostname']}")

if __name__ == "__main__":
    # Display the banner
    display_banner()

    # Define the IP range to scan (adjust based on your network)
    ip_range = "192.168.1.1/24"

    print(f"Scanning network {ip_range}...\n")
    devices = scan_network(ip_range)
    display_devices(devices)
