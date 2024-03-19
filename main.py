import scapy.all as scapy # import the scapy library
import ipaddress # import ipaddress library to get the ips in the subnet
import logging # for suppression of errors during scan

# NPcap 1.79 should be installed in Windows for the scapy library to work
# https://npcap.com/#download

# An explanation of why ICMP and TCP are being used as the packets to perform these scanning operations, instead of other protocol of packets. [10]
# My answer:
#   ICMP is used for diagnostic purposes, such as checking if a host is reachable (ping) and gathering network condition information.
#   TCP is used to establish and maintain connections between devices and is employed in scanning to check for open ports on remote systems.
#   These protocols are chosen for their simplicity, efficiency, and widespread support across different network devices and operating systems, making them reliable choices for network scanning tasks.

# this function suppreses any errors during the scan
def suppress_errors():
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# banner
def banner():
    print("===============================\nNETWORK SCANNER\n===============================")

# this function will get the input from the user. 
def get_inputs():
    ip_list = []
    port_num = None
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
        mode = input("Please select the mode number:\n1 - ICMP\n2 - TCP\n: ")
        if mode in ['1','2']:
            if mode == '2':
                try:
                    port_num = int(input("Please enter the destination port number: "))
                    validOption = True
                except ValueError:
                    print("\033[0;31m*** Incorrect Input: Not a valid port number...\033[0m")
            else:
                validOption = True
        else:
            print("\033[0;31m*** Incorrect Input: Invalid mode...\033[0m")

    return ip_list, mode, port_num
    
# this function is for crafting of ICMP packets
def craft_icmp_packets(ip):
    ip_destination = scapy.IP(dst=ip)
    request_type = scapy.ICMP()  # ICMP packet
    packet = ip_destination / request_type # create the packet
    return packet

# this function is for crafting of TCP packets
def craft_tcp_packets(ip,port_num):
    ip_destination = scapy.IP(dst=ip)
    request_type = scapy.TCP(dport=port_num,flags="S")  # TCP packet
    packet = ip_destination / request_type # create the packet
    return packet

# this function is for sending request and checking the response from each ip
def get_response(ip_list,mode,port_num=None):
    live_ips = [] # create an empty list of live ips
    
    # loop thru each ip in the ip list
    for ip in ip_list:
        # icmp
        if mode == '1': 
            print("mode 1 selected")
            packet = craft_icmp_packets(ip) # crafted packet
            response = scapy.sr1(packet, timeout=1, verbose=True) # create the response object
            if response and response.haslayer(scapy.ICMP) and response[scapy.ICMP].type == 0: # check if the response is ICMP and if the type field is 0
                print(f"\u001b[32m{ip} is live\033[0m\n")
                live_ips.append(ip) # if live, append it to the list of live ips
            else:
                print(f"\033[0;31m{ip} is unreachable\033[0m\n")
        # tcp
        elif mode == '2':
            packet = craft_tcp_packets(ip,port_num) # crafted packet
            response = scapy.sr1(packet, timeout=1, verbose=True) # create the response object
            if response and response.haslayer(scapy.TCP) and response[scapy.TCP].flags == 0x12: # checks if the response has TCP layer and if the  flag is 0x12.
                print(f"\u001b[32m{ip} is live\033[0m\n")
                live_ips.append(ip) # if live, append it to the list of live ips
            else:
                print(f"\033[0;31m{ip} is unreachable\033[0m\n")

    return live_ips


def report(live_ips):
    print("***Live IPs are:")
    for live_ip in live_ips:
        print(f"\u001b[32m{live_ip}\033[0m\n") # print live ips

# main function
def main():
    suppress_errors() # comment this to see errors during scan
    banner() # program banner
    ip_list, mode, port_num = get_inputs() # get and error check the user input
    live_ips= get_response(ip_list,mode,port_num) # get live ips
    report(live_ips) # print the list if live ips

main()


