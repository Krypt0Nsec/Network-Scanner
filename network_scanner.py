#!/usr/bin/env python
import scapy.all as scapy
# import optparse
import argparse
# #######################
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip_range", help="You should enter to IP range.")
    options = parser.parse_args()

    if not options.ip_range:
        parser.error("[-] Please Enter IP_RANGE, Use --help For More Info.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # scapy.ls(scapy.ARP()) => Show the parameters that can be used.
    arp_request_broadcast = broadcast / arp_request
    #arp_request_broadcast.show()
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip" : element[1].psrc, "mac" : element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(results_list):
    print("_" * 50)
    print("\n#NO\tIP\t\tMAC ADDRESS")
    counter = 0
    for client in results_list:
        counter += 1
        print("\n" + str([counter]) + "\t" + str(client["ip"]) + "\t" + str(client["mac"]))
    print("\n")

options = get_arguments()
scan_result = scan(options.ip_range)
print_result(scan_result)