import scapy.all as scapy  # import the scapy library
import ipaddress
import logging


def suppress_errors():
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def banner():
    print(
        r"""
    Exploring the uncharted regions of Cyberspace!"
                        .   *        .       .
         *      -0-
            .                .  *       - )-
         .      *       o       .       *
   o                |
             .     -O-
  .                 |        *      .     -0-
         *  o     .    '       *      .        o
                .         .        |      *
     *             *              -O-          .
           .             *         |     ,
                  .           o
          .---.
    =   _/__~0_\_     .  *            o       '
   = = (_________)             .
                   .                        *
         *               - ) -       *
                .               .
    """
    )


def get_inputs():
    ip_list = []
    port_num = None
    port_range = []
    # check if input is valid IPv4
    validInput = False
    while validInput == False:
        cidr = input("Please enter the IP address or CIDR notation: ").strip()
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            for ip in network.hosts():
                ip_list.append(str(ip))
            validInput = True
        except ValueError:
            print(
                "\033[0;31m*** Incorrect Input: Please enter a valid IP address. (e.g. 192.168.2.0/24)\033[0m"
            )

    # check if option is in range
    validOption = False
    while validOption == False:
        mode = input(
            "Modes:\n1 - ICMP\n2 - TCP\n3 - Port Scan\nPlease select the mode: "
        )
        if mode in ["1", "2", "3"]:
            if mode == "2":
                try:
                    port_num = int(input("Please enter the destination port number: "))
                    validOption = True
                except ValueError:
                    print(
                        "\033[0;31m*** Incorrect Input: Not a valid port number...\033[0m"
                    )
            elif mode == "3":
                try:
                    port_range_lower = int(
                        input("Please enter the lowest port number: ")
                    )
                    port_range_upper = int(
                        input("Please enter the highest port number: ")
                    )
                    port_range = list(range(port_range_lower, port_range_upper + 1))
                    validOption = True
                except ValueError:
                    print(
                        "\033[0;31m*** Incorrect Input: Not a valid port number...\033[0m"
                    )
                validOption = True
            else:
                validOption = True
        else:
            print("\033[0;31m*** Incorrect Input: Invalid mode...\033[0m")

    return ip_list, mode, port_num, port_range


# this is for crafting of ICMP packets
def craft_icmp_packets(ip):
    ip_destination = scapy.IP(dst=ip)
    request_type = scapy.ICMP()  # ICMP packet
    packet = ip_destination / request_type  # create the packet
    return packet


# this is for crafting of TCP packets
def craft_tcp_packets(ip, port_num):
    ip_destination = scapy.IP(dst=ip)
    request_type = scapy.TCP(dport=port_num, flags="S")  # TCP packet
    packet = ip_destination / request_type  # create the packet
    return packet


# this is for getting the response from each ip
def get_response(ip_list, mode, port_num=None, port_range=None):
    live_ips = []
    live_port = []
    # loop thru each ip in the ip list
    for ip in ip_list:

        if mode == "1":  # host discovery using ICMP packet
            packet = craft_icmp_packets(ip)  # crafted packet
            response = scapy.sr1(
                packet, timeout=1, verbose=False
            )  # create the response object
            if (
                response
                and response.haslayer(scapy.ICMP)
                and response[scapy.ICMP].type == 0
            ):
                print(f"\u001b[32m{ip} is live\033[0m")
                live_ips.append(ip)
            else:
                print(f"\033[0;31m{ip} is unreachable\033[0m")

        elif mode == "2":  # host discovery using TCP packet
            packet = craft_tcp_packets(ip, port_num)  # crafted packet
            response = scapy.sr1(
                packet, timeout=1, verbose=False
            )  # create the response object
            if (
                response
                and response.haslayer(scapy.TCP)
                and response[scapy.TCP].flags == 0x12
            ):
                print(f"\u001b[32m{ip}:{port_num} is live\033[0m")
                live_ips.append(ip)
                live_port.append(port_num)
            else:
                print(f"\033[0;31m{ip}:{port_num} is unreachable\033[0m")

        elif mode == "3":  # this is for port scan per IP
            for port in port_range:
                packet = craft_tcp_packets(ip, port)
                response = scapy.sr1(
                    packet, timeout=1, verbose=False
                )  # create the response object
                if (
                    response
                    and response.haslayer(scapy.TCP)
                    and response[scapy.TCP].flags == 0x12
                ):
                    print(f"\u001b[32m{ip}:{port} is open\033[0m")
                    live_ips.append(ip)
                    live_port.append(port)
                # uncomment this if you want to list closed ports
                # else:
                #     print(f"\033[0;31m{ip}:{port} is closed\033[0m")

    return live_ips, live_port


# main function
def main():
    suppress_errors()  # comment this to see errors during scan
    banner()
    ip_list, mode, port_num, port_range = (
        get_inputs()
    )  # get and error check the user input
    get_response(ip_list, mode, port_num, port_range)  # get live ips


main()
