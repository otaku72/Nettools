from scapy.all import ARP, Ether, srp
import sys

def scan_network(ip_range):
    """
    Scan the network for connected devices.
    :param ip_range: The IP range to scan (e.g., '192.168.1.1/24')
    :return: A list of devices with their IP and MAC addresses.
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
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def display_devices(devices):
    """
    Display the list of devices.
    :param devices: A list of devices with IP and MAC addresses.
    """
    print("Connected Devices:")
    print("-------------------")
    print("IP Address\t\tMAC Address")
    print("-------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

if __name__ == "__main__":
    # Define the IP range to scan (adjust based on your network)
    ip_range = "192.168.1.1/24"

    print(f"Scanning network {ip_range}...")
    devices = scan_network(ip_range)
    display_devices(devices)
