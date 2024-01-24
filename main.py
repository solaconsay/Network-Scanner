import scapy.all as scapy # import the scapy library
import ipaddress
import logging

def suppress_errors():
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def get_inputs():
    ip_list = []

    # check if input is valid IPv4
    validInput = False
    while validInput == False:
        cidr = input("Please enter the network address: ")          
        try:
            network = ipaddress.IPv4Network(cidr, strict=False) 
            for ip in network.hosts():
                ip_list.append(str(ip))
            validInput = True
        except ValueError:
            print("\033[0;31m*** Incorrect Input: Please enter a valid IP address. (e.g. 192.168.2.0/24)\033[0m")
    
    # check if option is in range
    validOption = False
    while validOption == False:
        mode = input("Please select the mode: [1]-ICMP [2]-TCP: ")
        if mode in ['1','2']:
            validOption = True
        else:
            print("\033[0;31m*** Incorrect Input: Please select 1 or 2 only...\033[0m")

    return ip_list, mode
    
# this is for crafting of packets
def craft_packets(ip):

    # ICMP packet crafting
    request_type = scapy.ICMP()  
    ip_destination = scapy.IP(dst=ip)
    packet = ip_destination / request_type

    # TCP packet crafting

    return packet

# this is for getting the response from each ip
def get_response(ip_list):
    live_ips = []
    
    # loop thru each ip in the ip list
    for ip in ip_list:
        packet = craft_packets(ip) # crafted packet
        response = scapy.sr1(packet, timeout=1, verbose=True) # create the response object
        
        if response and response.haslayer(scapy.ICMP) and response[scapy.ICMP].type == 0: # check response if ip is live
            print(f"\u001b[32m{ip} is live\033[0m\n")
            live_ips.append(ip)
        else:
            print(f"\033[0;31m{ip} is unreachable\033[0m\n")
    return live_ips


def report(live_ips):
    for live_ip in live_ips:
        print(f"live IPs are: {live_ip}") # print live ips

# main function
def main():
    suppress_errors() # comment this to see errors during scan
    ip_list, mode = get_inputs() # get and error check the user input
    live_ips = get_response(ip_list) # get live ips
    report(live_ips)

main()


