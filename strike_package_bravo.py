
class Strike_Package_Bravo:
    
    def __init__(self,ip) -> None:
        self.ip = ip 
    

    def nmap_scan(self): 
        import nmap3
        
        port_services = []
        nm = nmap3.Nmap()
        result = nm.nmap_version_detection(self.ip,arg='-sV',args='-p-')
        for open_port in result[self.ip]['ports']:
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

    


