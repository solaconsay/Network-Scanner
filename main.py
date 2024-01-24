import scapy.all as scapy # import the scapy library
import ipaddress
import logging

def suppress_errors():
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


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
        mode = input("Please select the mode: [1]-ICMP [2]-TCP: ")
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
    
# this is for crafting of ICMP packets
def craft_icmp_packets(ip):
    ip_destination = scapy.IP(dst=ip)
    request_type = scapy.ICMP()  # ICMP packet
    packet = ip_destination / request_type # create the packet
    return packet

# this is for crafting of TCP packets
def craft_tcp_packets(ip,port_num):
    ip_destination = scapy.IP(dst=ip)
    request_type = scapy.TCP(dport=port_num,flags="S")  # TCP packet
    packet = ip_destination / request_type # create the packet
    return packet

# this is for getting the response from each ip
def get_response(ip_list,mode,port_num=None):
    live_ips = []
    
    # loop thru each ip in the ip list
    for ip in ip_list:
        
        if mode == 1:
            print("mode 1 selected")
            packet = craft_icmp_packets(ip) # crafted packet
            response = scapy.sr1(packet, timeout=1, verbose=True) # create the response object
            if response and response.haslayer(scapy.ICMP) and response[scapy.ICMP].type == 0:
                print(f"\u001b[32m{ip} is live\033[0m\n")
                live_ips.append(ip)
            else:
                print(f"\033[0;31m{ip} is unreachable\033[0m\n")

        elif mode == 2:
            packet = craft_tcp_packets(ip,port_num) # crafted packet
            response = scapy.sr1(packet, timeout=1, verbose=True) # create the response object
            if response and response.haslayer(scapy.TCP) and response[scapy.TCP].flags == 0x12:
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
    
    ip_list, mode, port_num = get_inputs() # get and error check the user input
    get_response(ip_list,mode,port_num) # get live ips
    # report(live_ips)

main()


