from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import nmap3

class Strike_Package_Bravo:
    
    def nmap_scan(): 
        port_services = []
        
        ip_add = input("Please enter ip adress for scan: ")
        
        nm = nmap3.Nmap()
        
        result = nm.nmap_version_detection(ip_add,arg='-sV',args='-p-')
        for open_port in result[ip_add]['ports']:
            try:
                port_info = {
                    'port' : f"{open_port.get('portid')}",
                    'service' : f"{open_port['service'].get('name')}", 
                    'product' : f"{open_port['service'].get('product')}",
                    'version' : f"{open_port['service'].get('version')}"         
                }
                
                port_services.append(port_info)
            except KeyError:
                continue
                 
        return port_services
    
    def arp_scan():
        conn = []
        ip_range = input('Please enter a network you want to target: ')
        
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range),timeout=2)
        
        for snd,rcv in ans:
            conn.append(f"""IP :{rcv.sprintf(r"%ARP.psrc%")}        MAC :{rcv.sprintf("%Ether.dst%")}""")
        
        return conn

  


