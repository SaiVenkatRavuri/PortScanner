import sys
import socket
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.l2 import ARP, Ether
import argparse

conf.verb = 0

def icmp_scan(target):
    try:
        ans = sr1(IP(dst=target)/ICMP(), timeout=3, verbose=0)
        return "Host is UP" if ans else "Host is DOWN"
    except Exception as e:
        return f"Error: {str(e)}"

def tcp_port_scan(target, ports):
    results = {}
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((target, port))
            s.close()
            results[port] = "OPEN" if result == 0 else "CLOSED"
        except Exception as e:
            results[port] = f"Error: {str(e)}"
    return results

def arp_scan(network):
    try:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=0)
        hosts = []
        for sent, received in ans:
            hosts.append({'IP': received.psrc, 'MAC': received.hwsrc})
        return hosts
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("target", help="Target IP address or network")
    parser.add_argument("-p", "--ports", help="Ports to scan (comma-separated)")
    args = parser.parse_args()
    
    target = args.target
    ports = [int(port) for port in args.ports.split(",")] if args.ports else [80, 443, 8080]
    
    print("Network Scanner")
    print("===============")
    print(f"Target: {target}")
    
    icmp_result = icmp_scan(target)
    
    tcp_results = tcp_port_scan(target, ports)
    
    if "/" not in target:
        network = ".".join(target.split(".")[0:3]) + ".0/24"
    else:
        network = target
        
    arp_results = arp_scan(network)
    
    print("\nScan Results:")
    print("=============")
    
    print(f"ICMP Scan: {icmp_result}")
    
    print("\nTCP Port Scan:")
    for port, status in tcp_results.items():
        print(f"Port {port}: {status}")
    
    print("\nARP Scan:")
    if isinstance(arp_results, list):
        if arp_results:
            for host in arp_results:
                print(f"IP: {host['IP']}, MAC: {host['MAC']}")
        else:
            print("No hosts found")
    else:
        print(arp_results)

if __name__ == "__main__":
    main()
