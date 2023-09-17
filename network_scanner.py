#!/usr/bin/env python

import scapy.all as scapy
import optparse


def get_ip():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest = "ip", help = "targeted IP address / IP range")
    (option, argument) = parser.parse_args()
    ip = option.ip
    return ip

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]
    
    client_list = []
    
    for element in answered:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list
    
def print_list(result_list):
    print("Ip Address\t\t\tMAC Address\n----------------------------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t\t" + client["mac"])

scan_result = scan(get_ip())

print_list(scan_result)