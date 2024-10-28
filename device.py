from scapy.all import ARP, Ether, srp
import ipaddress

def scan_network(network_range):
    """
    Scan the network to find live hosts using ARP requests.
    """
    arp = ARP(pdst=str(ipaddress.ip_network(network_range)))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    
    result = srp(packet, timeout=2, verbose=0, multi=True)[0]

    
    return [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]

def main():
    
    network_range = "192.168.1.0/24"

    
    devices = scan_network(network_range)
    print("Found devices:", devices)

if __name__ == "__main__":
    main()

