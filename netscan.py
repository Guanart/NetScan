#!/usr/bin/env python3

# ------------------------------------------------------------------
# DESCRIPTION
#    Analyse your entire current network.
#    Features: host discovery, port scanner and banner grabing.
#
# OPTIONS
#    -i [network_interface]        Specifies the network interface to use
#    -i                            Display all avaible network interfaces
#    -h, --help                    Print this help
#
# EXAMPLES
#    $netscan.py -i
#    $netscan.py -i eth0

# ------------------------------------------------------------------

from scapy.all import *
import socket
import argparse
import logging
import netaddr, netifaces
import json
import requests

# Logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# Banner
def print_banner():
    banner = '''
     _   _      _   ____                  
    | \ | | ___| |_/ ___|  ___ __ _ _ __  
    |  \| |/ _ \ __\___ \ / __/ _` | '_ \ 
    | |\  |  __/ |_ ___) | (_| (_| | | | |
    |_| \_|\___|\__|____/ \___\__,_|_| |_| v1.0
    
    By Gonzalo Benito
    Email: gu4n4rt@gmail.com
    Github: https://github.com/guanart
    
    '''
    print(banner)

##############################################################################################
###                                     Host Discovery                                     ###
##############################################################################################

### Host Discovery with ARP packets using Scapy
def host_discovery(network_cidr):
    ip_target = str(network_cidr)
    arp = ARP(pdst=ip_target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=False)[0]
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

### Hosts Info
class cliente():
    def __init__(self, ip_address, mac_address):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.tcp_ports = []
        self.udp_ports = []
        self.tcp_ports_results = []        
        self.udp_ports_results = []
        self.tcp_banner = []
        self.udp_banner = []

    def ip(self):
        return self.ip_address
    
    def mac(self):
        return self.mac_address

def client_instance(clients):
    clients_instances = dict()
    client_number = 1
    for client in clients:
        client_name = str(f"client{client_number}")
        client_addresses = cliente(client['ip'], client['mac'])
        clients_instances[client_name] = client_addresses
        client_number = client_number + 1
    return clients_instances

def host_info(clients_instances):
    print('='*45+"\nAvailable devices in the network "+str(network_cidr)+":")
    print("IP" + " "*18+"MAC")
    for client_name in clients_instances:
        client_ip = clients_instances[client_name].ip()
        client_mac = clients_instances[client_name].mac()
        print("{:16}    {}".format(client_ip, client_mac))
    print('='*45+'\n')

##############################################################################################
###                                   Port Scanning                                        ###
##############################################################################################

# Scan Types
def stealth_scan(dst_ip, dst_port):
    src_port = RandShort()
    stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=5)
    if stealth_scan_resp is None:
        # return "Filtered"
        pass
    elif (stealth_scan_resp.haslayer(TCP)):
        if (stealth_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=5)
            return "Open"
        elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
            #return "Closed"
            pass
    elif (stealth_scan_resp.haslayer(ICMP)):
        if (int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            #return "Filtered"
            pass

def udp_scan(dst_ip, dst_port):
    udp_packet = IP(dst=dst_ip)/UDP(dport=dst_port)
    udp_scan_resp = sr1(udp_packet,timeout=5)
    
    if udp_scan_resp is None:
        retrans = []
        for count in range(0,3):
            retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=5))
        for item in retrans:
            if (str(type(item))!="<type 'NoneType'>"):
                return "Open|Filtered"
            elif (item.haslayer(UDP)):
                return "Open"
            elif(item.haslayer(ICMP)):
                if( int (item.getlayer(ICMP).type)==3 and int(item.getlayer(ICMP).code)==3):
                    #return "Closed"
                    pass
                elif(int(item.getlayer(ICMP).type)==3 and int(item.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    #return "Filtered"
                    pass

# Port Scanning Main
def port_discovery(clients_instances):
    dst_ports = [21,80] # Modify
        
    for client_name in clients_instances:
        for dst_port in dst_ports:
            # TCP
            result_tcp = stealth_scan(clients_instances[client_name].ip(), int(dst_port))
            if result_tcp is not None:
                clients_instances[client_name].tcp_ports.append(dst_port)
                clients_instances[client_name].tcp_ports_results.append(f'({result_tcp})')
            # UDP
            result_udp = stealth_scan(clients_instances[client_name].ip(), int(dst_port))
            if result_udp is not None:
                clients_instances[client_name].udp_ports.append(dst_port)
                clients_instances[client_name].udp_ports_results.append(f'({result_udp})')

##############################################################################################
###                                     Banner Grabing                                     ###
##############################################################################################

def banner_grabing(clients_instances):    
    def return_banner(ip, port):
        try:
            sock = socket.socket()
            socket.setdefaulttimeout(5)
            sock.connect((ip, port))
            banner = str(sock.recv(1024)).strip("b'220- ").split('\\r')[0]
            return banner
        except Exception as e:
            banner = 'Unknow'
            return banner

    for client_name in clients_instances:
        ip_address = clients_instances[client_name].ip_address
        tcp_ports = clients_instances[client_name].tcp_ports
        udp_ports = clients_instances[client_name].udp_ports
        tcp_banner = clients_instances[client_name].tcp_banner
        udp_banner = clients_instances[client_name].udp_banner
   
        # TCP
        for dst_port in tcp_ports:
            banner = return_banner(ip_address, dst_port)
            tcp_banner.append(banner)

        # UDP
        for dst_port in udp_ports:
            banner = return_banner(ip_address, dst_port)
            udp_banner.append(banner)

##############################################################################################
###                                    Print Results                                       ###
##############################################################################################

def print_results(clients_instances):
    for client_name in clients_instances:
        tcp_range = range(len(clients_instances[client_name].tcp_ports))
        udp_range = range(len(clients_instances[client_name].udp_ports))
        
        # Print IP address
        print("\nIP {:16}\n{}".format(clients_instances[client_name].ip_address, "="*17))
        
        # Print TCP ports
        print("\n        TCP:\n")
        for i in tcp_range:
            tcp_port = clients_instances[client_name].tcp_ports[i]
            tcp_ports_results = clients_instances[client_name].tcp_ports_results[i]
            tcp_banner = clients_instances[client_name].tcp_banner[i]
            if tcp_port is not None:
                print("{:16} {:4}:    {}".format(tcp_port, tcp_ports_results, tcp_banner))
        
        # Print UDP ports
        print("\n        UDP:\n")
        for i in udp_range:
            udp_port = clients_instances[client_name].udp_ports[i]
            udp_ports_results = clients_instances[client_name].udp_ports_results[i]
            udp_banner = clients_instances[client_name].udp_banner[i]
            if udp_port is not None:
                print("{:16} {:4}:    {}".format(udp_port, udp_ports_results, udp_banner))

        print('.'*40+'\n')

##############################################################################################
###                                         Export                                         ###
##############################################################################################

# Generate JSON file
def export_json(clients_instances, filename='results.json'):
    results = {}
    status = '\nGenerando fichero results.json. . . .'+' '*8
    print(status.strip('\n'), end='')

    for client_name in clients_instances:
        json_obj = clients_instances[client_name].__dict__
        results[f'{client_name}'] = json_obj
        
    with open(filename, 'w') as file:
        json.dump(results, file, indent=4)
    
    print('[OK]')

# Send JSON file to server
def send_json_post(file='results.json'):
    url = 'http://192.168.79.1/upload_results.php'
    status = f'Enviando resultados a {url}. . . .'+' '*8
    print(status.strip('\n'), end='')

    try:
        with open(file, "rb") as a_file:
            file_dict = {file: a_file}
            response = requests.post(url, files=file_dict)

        if response.ok:
            ok = '[OK]'
            print('{}'.format(ok))
    except:
        fail = '[FAIL]'
        print('{}'.format(fail))
    

##############################################################################################
###                                         Start                                          ###
##############################################################################################

# Arguments parser
parser = argparse.ArgumentParser(
    description=f'{print_banner()}Network Port Scanner. Execute with sudo permissions. Enter --help for more information',
    argument_default='-i')

parser.add_argument("-i", "--interfaz", help="Nombre de la interfaz de red a usar. Utilice '-i' para ver las interfaces disponibles", action="store_true")
parser.add_argument("adapter", nargs='?', default="empty")
args = parser.parse_args()

# Interface and Network Information
if args.interfaz == True:
    if args.adapter == 'empty':
        interfaces = netifaces.interfaces()
        count = 1
        print('Especifique una interfaz de red a utilizar.\n\nInterfaces disponibles:')
        for i in interfaces:
            print(f'    {count}. {i}')
            count += 1
    else:
        interfaz = args.adapter
        try:
            interfaz_info = netifaces.ifaddresses(interfaz)[netifaces.AF_INET][0]
            ip_address = interfaz_info['addr']
            netmask = interfaz_info['netmask']

            cidr = netaddr.IPNetwork('%s/%s' % (ip_address, netmask))
            network = cidr.network
            network_cidr = netaddr.IPNetwork('%s/%s' % (network, netmask))
        except ValueError:
            print('Ingrese una interfaz válida.')
else:
    parser.print_help()

##############################################################################################
###                                         Main                                          ###
##############################################################################################

def main():
    # Clients on our network
    if 'network_cidr' in globals():
        print("[+] Scan started\n")
        clients = host_discovery(network_cidr)
        # Instances of clients on dictionary
        clients_instances = client_instance(clients)
        # Info
        host_info(clients_instances)
        # Port discovery with the client objects
        port_discovery(clients_instances)
        # Banner grabbing with Sockets
        banner_grabing(clients_instances)
        # Print results
        print_results(clients_instances)
        # Export results to JSON file
        export_json(clients_instances)
        # Upload JSON results to web server
        send_json_post()
        # End
        print("\n[*] Scan completed\n")

if __name__ == "__main__":
    main()