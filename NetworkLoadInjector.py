import multiprocessing
import os.path
import random
import subprocess
import tempfile
import threading
import time
from multiprocessing import Pool, cpu_count, Queue
from urllib.request import urlopen

# SUPPORT METHODS

def current_ms():
    """
    Reports the current time in milliseconds
    :return: long int
    """
    return round(time.time() * 1000)

def random_ip():
    """
    Generates a random IP address
    :return: str
    """
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


# ABSTRACT CLASS FOR INJECTIONS

class LoadInjector:
    """
    Abstract class for Injecting Errors in the System
    Should you want to implement your own injector, just extend/override this class
    """

    def __init__(self, tag: str = '', duration_ms: float = 1000):
        """
        Constructor
        """
        self.valid = True
        self.tag = tag
        self.duration_ms = duration_ms
        self.inj_thread = None
        self.completed_flag = True
        self.injected_interval = []
        self.init()

    def is_valid(self) -> bool:
        return self.valid

    def init(self):
        """
        Override needed only if the injector needs some pre-setup to be run. Default is an empty method
        :return:
        """
        pass

    def inject_body(self):
        """
        Abstract method to be overridden
        """
        pass

    def inject(self):
        """
        Caller of the body of the injection mechanism, which will be executed in a separate thread
        """
        self.inj_thread = threading.Thread(target=self.inject_body(), args=())
        self.inj_thread.start()
        return self.inj_thread 

    def is_injector_running(self):
        """
        True if the injector has finished working (end of the 'injection_body' function)
        """
        return not self.completed_flag

    def force_close(self):
        """
        Tries to force-close the injector
        """
        pass

    def get_injections(self) -> list:
        """
        Returns start-end times of injections exercised with this method
        """
        return self.injected_interval

    def get_name(self) -> str:
        """
        Abstract method to be overridden, provides a string description of the injector
        """
        return "[" + self.tag + "]Injector" + "(d" + str(self.duration_ms) + ")"

    @classmethod
    def fromJSON(cls, job):
        """ 
        This abstract function allows to create an instance of an injector from a json description of the injector
        :param job: the JSON description of the injector
        :return: the injector object (subclass of LoadInjector) """
        
        pass




# NETWORK TRAFFIC INJECTION

from scapy.all import (
    TCP, 
    UDP, 
    SCTP,
)
from scapy.all import send, fragment, show_interfaces, Ether, Raw, DNS, DNSQR, DNSRR
from scapy.all import (
    IP,      # Internet Protocol v4
    IPv6,    # Internet Protocol v6
    ARP,     # Address Resolution Protocol
    ICMP,    # Internet Control Message Protocol
    GRE,     # Generic Routing Encapsulation
    AH,      # Authentication Header
    ESP      # Encapsulating Security Payload
)
import random
import time

L4_PROTOCOLS = [UDP, TCP]
L3_PROTOCOLS = [IP, IPv6, ARP, ICMP, GRE, AH, ESP]


class NetworkLoadInjector(LoadInjector):
    """
    NetworkTrafficInjection class for simulating network traffic anomalies.
    - Port Scanning
    - Packet Flooding
    - IP Spoofing
    - Oversized Packets
    - Fragmented Packets
    - Malformed Packets
    - Protocol_anomalies
    """

    def __init__(self, tag: str = '', duration_ms: float = 5000, target_ip: str = "127.0.0.1", target_port: int = 80):
        """
        Constructor for NetworkTrafficInjection
        :param tag: Tag for the injector
        :param duration_ms: Duration of the injection in milliseconds
        :param target_ip: Target IP for the injection
        """
        super().__init__(tag, duration_ms)
        self.target_ip = target_ip
        self.target_port = target_port
        self.chosen_method = None
        #self.chosenMethod = random.choice([self.port_scanning, self.packet_flooding, self.ip_spoofing, self.oversized_packets, self.fragmented_packets, self.malformed_packets, self.protocol_anomalies])
        # Set default interface
        #self.iface = conf.iface
        # Resolve MAC address
        #self.target_mac = self.get_mac(target_ip)
        
    """    
    def randomize_method_choice(self):
        
        Randomly selects an anomaly method and executes it.
        
        # Randomly choose an injection type
        anomaly_methods = [self.ip_spoofing]
        
        self.chosen_method = random.choice(anomaly_methods)
 """

    """ def get_mac(self, ip):
        try:
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp1(packet, timeout=3, verbose=False)#, iface=self.iface)
            if result:
                return result.hwsrc
            return None
        except Exception as e:
            print(f"Error resolving MAC address: {e}")
            return None


    def send_packet(self, packet, verbose: bool = False):
        try:
            if self.target_mac:
                # Add Ethernet layer with resolved MAC
                packet = Ether(dst=self.target_mac)/packet
            sendp(packet, verbose=verbose)#, iface=self.iface)
        except Exception as e:
            print(f"Error sending packet: {e}") """


    def inject_body(self):
        """
        Main injection logic. Randomly selects an anomaly method and executes it.
        """
        self.completed_flag = False
        start_time = current_ms()
            
        self.chosen_method()

        # Ensure injection runs for the specified duration
        while current_ms() - start_time < self.duration_ms:
            time.sleep(0.01)

        self.injected_interval.append({'start': start_time, 'end': current_ms()})
        self.completed_flag = True


    def get_name(self) -> str:
        """
        Returns a descriptive name for the injector.
        """
        pass

    @classmethod
    def fromJSON(cls, job):
        """ 
        Create an instance of the NetworkTrafficInjection class from a JSON definition. """
        
        if job is not None:
            if 'type' in job:
                if job['type'] == "PortScanningInjection":
                    return PortScanningInjector.fromJSON(job)
                elif job['type'] == "PacketFloodingInjection":
                    return PacketFloodingInjector.fromJSON(job)
                elif job['type'] == "IPSpoofingInjection":
                    return IPSpoofingInjector.fromJSON(job)
                elif job['type'] == "OversizedPacketsInjection":
                    return OversizedPacketsInjector.fromJSON(job)
                elif job['type'] == "FragmentedPacketsInjection":
                    return FragmentedPacketsInjector.fromJSON(job)
                elif job['type'] == "MalformedPacketsInjection":
                    return MalformedPacketsInjector.fromJSON(job)
                elif job['type'] == "ProtocolAnomaliesInjection":
                    return ProtocolAnomaliesInjector.fromJSON(job)
        return None

        
           
        
# INJECTOR IMPLEMENTATIONS        

class PortScanningInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, source_ip:str = None, target_ip: str = "127.0.0.1"):
        super().__init__(tag, duration_ms, target_ip)
        self.chosen_method = self.port_scanning
        self.source_ip = source_ip
    
    def port_scanning(self):
        """
        Simulate port scanning by sending SYN packets to a range of ports.
        """
        end_time = time.time() + (self.duration_ms / 1000)
        print(f"[{self.tag}] Starting port scanning on {self.target_ip}/{self.target_port}")
        
        port = 0
        while time.time() < end_time:  # Scan ports 1-1024
            #defining a random source ip if its not defined
            src_ip = random_ip() if(self.source_ip==None) else self.source_ip
            print("Sending packet to IP: " + self.target_ip + "/" + str(port))
            l4_protocol = random.choice(L4_PROTOCOLS)
            packet = IP(src=src_ip, dst=self.target_ip)/l4_protocol(sport = random.randint(1, 60000), dport=port, flags=random.choice(["S","A","F"]))
            send(packet,   verbose=False)
            port += 1
        
    def get_name(self) -> str:
        """
        Returns a descriptive name for the injector.
        """
        return f"[{self.tag}]{self.__class__.__name__}(duration: {self.duration_ms})"
    
    @classmethod
    def fromJSON(cls, job):   
        tag=(job['tag'] if 'tag' in job else '')
        duration_ms=(job['duration_ms'] if 'duration_ms' in job else 1000)
        source_ip = (job['source_ip'] if 'source_ip' in job else None)
        target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1')
        return PortScanningInjector(tag, duration_ms, source_ip, target_ip)  


class PacketFloodingInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, source_ip:str = None, target_ip: str = "127.0.0.1", target_port: int = 80):
        super().__init__(tag, duration_ms, target_ip, target_port)
        self.chosen_method = self.packet_flooding
        self.source_ip = source_ip
   
    def packet_flooding(self):
        """
        Simulate packet flooding by sending many SYN packets to a single port.
        """
        print(f"[{self.tag}] Starting packet flooding on {self.target_ip}/{self.target_port}")
        end_time = time.time() + (self.duration_ms / 1000)
        src_ip = random_ip() if(self.source_ip==None) else self.source_ip
        while time.time() < end_time:
            packet = IP(src=src_ip, dst=self.target_ip)/TCP(sport = random.randint(1, 60000), dport=(random.randint(1,60000) if(self.target_port==None) else self.target_port), flags=random.choice(["S","A","F"]))
            send(packet,  verbose=False)
    
    def get_name(self) -> str:
        """
        Returns a descriptive name for the injector.
        """
        return f"[{self.tag}]{self.__class__.__name__}(duration: {self.duration_ms})"
    
    @classmethod
    def fromJSON(cls, job):
        tag=(job['tag'] if 'tag' in job else '')
        duration_ms=(job['duration_ms'] if 'duration_ms' in job else 1000)
        source_ip = (job['source_ip'] if 'source_ip' in job else None)
        target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1')
        target_port=(job['target_port'] if 'target_port' in job else 80)
        return PacketFloodingInjector(tag, duration_ms, source_ip, target_ip, target_port)
          

class IPSpoofingInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, target_ip: str = "127.0.0.1", target_port:int = 80):
        super().__init__(tag, duration_ms, target_ip, target_port)
        self.chosen_method = self.ip_spoofing
        
    def ip_spoofing(self):
        """
        Simulate IP spoofing by sending packets with random fake source IPs.
        """
        print(f"[{self.tag}] Starting IP spoofing towards  {self.target_ip}/{self.target_port}")
        end_time = time.time() + (self.duration_ms / 1000)
        while time.time() < end_time:
            fake_ip = random_ip()
            print("Sending packet to IP: " + self.target_ip + "/" + str(self.target_port))
            packet = IP(src=fake_ip, dst=self.target_ip)/TCP(sport = random.randint(1, 60000), dport=(random.randint(1,60000) if(self.target_port==None) else self.target_port), flags=random.choice(["S","A","F"]))
            send(packet, verbose=False)
    
    def get_name(self) -> str:
        """
        Returns a descriptive name for the injector.
        """
        return f"[{self.tag}]{self.__class__.__name__}(duration: {self.duration_ms})"
    
    @classmethod
    def fromJSON(cls, job):
        tag=(job['tag'] if 'tag' in job else '')
        duration_ms=(job['duration_ms'] if 'duration_ms' in job else 1000)
        target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1')
        target_port=(job['target_port'] if 'target_port' in job else 80)
        return IPSpoofingInjector(tag, duration_ms, target_ip, target_port)
    




class OversizedPacketsInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, source_ip:str = None, target_ip: str = "127.0.0.1", target_port: int = 80, size:int = 1000):
        super().__init__(tag, duration_ms, target_ip, target_port)
        self.chosen_method = self.oversized_packets
        self.size = size
        self.source_ip = source_ip
            
    def oversized_packets(self):
        """
        Send oversized packets to the target.
        """
        print(f"[{self.tag}] Sending oversized packets to  {self.target_ip}/{self.target_port}")
        
        end_time = time.time() + (self.duration_ms / 1000)
        payload = "X" * self.size  # Create a large payload
        while time.time() < end_time:
            #defining a random source ip if its not defined
            src_ip = random_ip() if(self.source_ip==None) else self.source_ip
            l4_protocol = random.choice(L4_PROTOCOLS)
            packet = IP(src=src_ip, dst=self.target_ip)/l4_protocol(sport = random.randint(1, 60000), dport = self.target_port)/Raw(load = payload) #IP(dst="192.168.1.8")/TCP(dport=80, sport=12345)/Raw(load="A" * 1000)     IP(dst=self.target_ip)/UDP(dport = 80, flags=random.choice(["S","A","F"]))#/Raw(load = payload)
            send(packet, verbose=False)        
    
    def get_name(self) -> str:
        """
        Returns a descriptive name for the injector.
        """
        return f"[{self.tag}]{self.__class__.__name__}(duration: {self.duration_ms})"
    
    @classmethod
    def fromJSON(cls, job):
        tag=(job['tag'] if 'tag' in job else '')
        duration_ms=(job['duration_ms'] if 'duration_ms' in job else 1000)
        source_ip = (job['source_ip'] if 'source_ip' in job else None)
        target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1')
        target_port=(job['target_port'] if 'target_port' in job else 80)
        size=(job['size'] if 'size' in job else 2000)    
        return OversizedPacketsInjector(tag, duration_ms, source_ip, target_ip, target_port, size)



class FragmentedPacketsInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, source_ip:str = None, target_ip: str = "127.0.0.1", target_port: int = 80, payload_size:int = 500, frag_size:int = 50):
        super().__init__(tag, duration_ms, target_ip, target_port)
        self.chosen_method = self.fragmented_packets
        self.payload_size = payload_size
        self.frag_size = frag_size
        self.source_ip = source_ip
        
    def fragmented_packets(self):
        """
        Send fragmented packets to the target.
        """
        print(f"[{self.tag}] Sending fragmented packets to  {self.target_ip}/{self.target_port}")
        
        while time.time() < end_time: 
            #defining a random source ip if its not defined
            src_ip = random_ip() if(self.source_ip==None) else self.source_ip
            
            #choosing the layer 4 protocol randomly
            l4_protocol = random.choice(L4_PROTOCOLS)
            
            #creating the packet to fragment
            payload = "A" * self.payload_size
            packet = IP(src=src_ip, dst=self.target_ip)/l4_protocol(sport = random.randint(1, 60000), dport=(random.randint(1,60000) if(self.target_port==None) else self.target_port))/Raw(load = payload)
            fragments = fragment(packet, fragsize = self.frag_size)
            end_time = time.time() + (self.duration_ms / 1000)  
            for frag in fragments:
                print("Sending fragmented packet to IP: " + self.target_ip + "/" + str(self.target_port))
                send(frag, verbose=False)
    
    def get_name(self) -> str:
        """
        Returns a descriptive name for the injector.
        """
        return f"[{self.tag}]{self.__class__.__name__}(duration: {self.duration_ms})"
    
    @classmethod
    def fromJSON(cls, job):
        tag=(job['tag'] if 'tag' in job else '')
        duration_ms=(job['duration_ms'] if 'duration_ms' in job else 1000)
        source_ip = (job['source_ip'] if 'source_ip' in job else None)
        target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1')
        target_port=(job['target_port'] if 'target_port' in job else 80)
        payload_size=(job['payload_size'] if 'payload_size' in job else 500)
        frag_size=(job['frag_size'] if 'frag_size' in job else 50)
        return FragmentedPacketsInjector(tag, duration_ms, source_ip, target_ip, target_port, payload_size, frag_size)





class MalformedPacketsInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, source_ip:str = None, target_ip: str = "127.0.0.1", target_port: int = 80):
        super().__init__(tag, duration_ms, target_ip, target_port)
        self.chosen_method = self.malformed_packets
        self.source_ip = source_ip

    def malformed_packets(self, num_packets=80):
        """
        Send malformed packets to the target.
        """
        print(f"[{self.tag}] Sending malformed packets to  {self.target_ip}/{self.target_port}")
        
        end_time = time.time() + (self.duration_ms / 1000)
        while time.time() < end_time:
            
            #defining a random source ip if its not defined
            src_ip = random_ip() if(self.source_ip==None) else self.source_ip
            
            # Example: Invalid TCP flag values, seq value, ack value, IP version, etc.
            packet = IP(src=src_ip, dst=self.target_ip, version=6)/TCP(sport = random.randint(1, 60000), dport=(random.randint(1,60000) if(self.target_port==None) else self.target_port), flags=random.randint(0,999), seq=random.randint(1000000, 4294967295),  ack=random.randint(100000,4294967295))  # error in flags and invalid seq number
            #print("Sending malformed packet to IP: " + self.target_ip + "/" + str(self.target_port))
            send(packet, verbose=True)

    def get_name(self) -> str:
        """
        Returns a descriptive name for the injector.
        """
        return f"[{self.tag}]{self.__class__.__name__}(duration: {self.duration_ms})"

    @classmethod
    def fromJSON(cls, job):
        tag=(job['tag'] if 'tag' in job else '')
        duration_ms=(job['duration_ms'] if 'duration_ms' in job else 1000)
        source_ip = (job['source_ip'] if 'source_ip' in job else None)
        target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1')
        target_port=(job['target_port'] if 'target_port' in job else 80)
        return MalformedPacketsInjector(tag, duration_ms, source_ip, target_ip, target_port)
        





class ProtocolAnomaliesInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, target_ip: str = "127.0.0.1", target_port: int = 80):
        super().__init__(tag, duration_ms, target_ip)
        self.chosen_method = self.protocol_anomalies
    
    def protocol_anomalies(self, num_packets=80):
        """
        Send unexpected protocol packets to the target.
        """
        print(f"[{self.tag}] Sending protocol anomalies to  {self.target_ip}/{self.target_port}")
        for _ in range(num_packets):
            # stacking more l3 layers togheter (this is wrong since they are the same level and cannot coexist). also adding a l4 layer after
            l4_protocol = random.choice(L4_PROTOCOLS)
            l3_protocol = random.choice(L3_PROTOCOLS)
            packet = IP(src=random_ip(), dst=self.target_ip)/l3_protocol()/l4_protocol(sport = random.randint(1, 60000), dport=(random.randint(1,60000) if(self.target_port==None) else self.target_port))
            send(packet,   verbose=False)           
    
    def get_name(self) -> str:
        """
        Returns a descriptive name for the injector.
        """
        return f"[{self.tag}]{self.__class__.__name__}(duration: {self.duration_ms})"
    
    @classmethod
    def fromJSON(cls, job):
        tag=(job['tag'] if 'tag' in job else ''),
        duration_ms=(job['duration_ms'] if 'duration_ms' in job else 1000),
        target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1'),
        target_port=(job['target_port'] if 'target_port' in job else 80)
        return ProtocolAnomaliesInjector(tag, duration_ms, target_ip, target_port)
    
            
             
             
             
             
             
             
             
             






class DNSCachePoisoningInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, source_ip: str = None, 
                 target_ip: str = "127.0.0.1", target_port: int = 53, 
                 poisoned_domain: str = "example.com", 
                 malicious_ip: str = "127.0.0.1"):
        super().__init__(tag, duration_ms, target_ip, target_port)
        self.chosen_method = self.dns_poison
        self.source_ip = source_ip
        self.poisoned_domain = poisoned_domain
        self.malicious_ip = malicious_ip
    
    #I want to specify that this attack method is mainly for generating realistic packets for this type of attack. for it to be really useful youd need to 
    #get a packet from the target, checking the udp port of the connection and using his ip. This way you can send a response message(qr = 1), so that the dns server
    #saves my(bad guy) ip into his cache for 24h(=ttl) and whenever i make a request to the server, he responds without checking since its in the cache
    def dns_poison(self):
        print(f"[{self.tag}] Sending DNS cache poisoning packets to {self.target_ip}/{self.target_port}")
        end_time = time.time() + (self.duration_ms / 1000)
        
        while time.time() < end_time:
            # Create spoofed response with high TTL
            dns_response = (
                IP(src=self.source_ip or random_ip(), dst=self.target_ip)/
                UDP(sport=53, dport=self.target_port)/
                DNS(
                    qr=1,  # Response
                    aa=1,  # Authoritative Answer
                    rd=1,  # Recursion Desired
                    ra=1,  # Recursion Available
                    id=random.randint(0, 65535),  # Random transaction ID
                    qd=DNSQR(qname=self.poisoned_domain),
                    an=DNSRR(
                        rrname=self.poisoned_domain,
                        type='A',
                        ttl=86400,  # 24 hours TTL
                        rdata=self.malicious_ip
                    )
                )
            )
            send(dns_response, verbose=False)
            
    @classmethod
    def fromJSON(cls, job):
        tag = (job['tag'] if 'tag' in job else '')
        duration_ms = (job['duration_ms'] if 'duration_ms' in job else 1000)
        source_ip = (job['source_ip'] if 'source_ip' in job else None)
        target_ip = (job['target_ip'] if 'target_ip' in job else '192.168.1.1')
        target_port = (job['target_port'] if 'target_port' in job else 53)
        poisoned_domain = (job['poisoned_domain'] if 'poisoned_domain' in job else 'example.com')
        malicious_ip = (job['malicious_ip'] if 'malicious_ip' in job else '192.168.1.100')
        return cls(tag, duration_ms, source_ip, target_ip, target_port, poisoned_domain, malicious_ip)