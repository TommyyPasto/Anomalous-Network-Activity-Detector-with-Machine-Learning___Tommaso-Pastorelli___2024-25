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

from scapy.all import IP, TCP, UDP, ICMP, send, sendp, fragment, show_interfaces, Ether, ARP, srp1, conf
import random
import time

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

    def __init__(self, tag: str = '', duration_ms: float = 5000, target_ip: str = "127.0.0.1", target_port: int = 13000):
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
    def __init__(self, tag: str = '', duration_ms: float = 1000, target_ip: str = "127.0.0.1"):
        super().__init__(tag, duration_ms, target_ip)
        self.chosen_method = self.port_scanning
    
    def port_scanning(self):
        """
        Simulate port scanning by sending SYN packets to a range of ports.
        """
        print(f"[{self.tag}] Starting port scanning on {self.target_ip}/{self.target_port}")
        for port in range(1, 1024):  # Scan ports 1-1024
            print("Sending packet to IP: " + self.target_ip + "/" + str(port))
            packet = IP(dst=self.target_ip)/TCP(dport=port, flags="S")
            send(packet,   verbose=False)
        
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
        return PortScanningInjector(tag, duration_ms, target_ip)  


class PacketFloodingInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, target_ip: str = "127.0.0.1", target_port: int = 13000):
        super().__init__(tag, duration_ms, target_ip, target_port)
        self.chosen_method = self.packet_flooding
   
    def packet_flooding(self):
        """
        Simulate packet flooding by sending many SYN packets to a single port.
        """
        print(f"[{self.tag}] Starting packet flooding on {self.target_ip}/{self.target_port}")
        end_time = time.time() + (self.duration_ms / 1000)
        while time.time() < end_time:
            packet = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags="S")
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
        target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1')
        target_port=(job['target_port'] if 'target_port' in job else 13000)
        return PacketFloodingInjector(tag, duration_ms, target_ip, target_port)
          


class IPSpoofingInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, target_ip: str = "127.0.0.1", target_port: int = 13000):
        super().__init__(tag, duration_ms, target_ip, target_port)
        self.chosen_method = self.ip_spoofing
        
    def ip_spoofing(self):
        """
        Simulate IP spoofing by sending packets with random fake source IPs.
        """
        print(f"[{self.tag}] Starting IP spoofing towards  {self.target_ip}/{self.target_port}")
        end_time = time.time() + (self.duration_ms / 1000)
        spoofed_ips = [f"10.0.0.{i}" for i in range(1, 255)]  # Generate fake IPs
        while time.time() < end_time:
            fake_ip = random.choice(spoofed_ips)
            print("Sending packet to IP: " + self.target_ip + "/" + str(self.target_port))
            packet = IP(src=fake_ip, dst=self.target_ip)/TCP(dport=random.randint(13000, 14000), flags="S")
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
        target_port=(job['target_port'] if 'target_port' in job else 13000)
        return IPSpoofingInjector(tag, duration_ms, target_ip, target_port)
    


class OversizedPacketsInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, target_ip: str = "127.0.0.1", target_port: int = 13000, size:int = 2000):
        super().__init__(tag, duration_ms, target_ip, target_port)
        self.chosen_method = self.oversized_packets
        self.size = size
            
    def oversized_packets(self):
        """
        Send oversized packets to the target.
        """
        print(f"[{self.tag}] Sending oversized packets to  {self.target_ip}/{self.target_port}")
        payload = "X" * random.randrange(self.size, self.size + 5000, 1)  # Create a large payload
        end_time = time.time() + (self.duration_ms / 1000)
        while time.time() < end_time:
            packet = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags="S")/payload
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
        target_port=(job['target_port'] if 'target_port' in job else 13000)
        size=(job['size'] if 'size' in job else 2000)    
        return OversizedPacketsInjector(tag, duration_ms, target_ip, target_port, size)



class FragmentedPacketsInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, target_ip: str = "127.0.0.1", target_port: int = 13000, payload_size:int = 5000, frag_size:int = 500):
        super().__init__(tag, duration_ms, target_ip, target_port)
        self.chosen_method = self.fragmented_packets
        self.payload_size = payload_size
        self.frag_size = frag_size
        
    def fragmented_packets(self):
        """
        Send fragmented packets to the target.
        """
        print(f"[{self.tag}] Sending fragmented packets to  {self.target_ip}/{self.target_port}")
        payload = "A" * self.payload_size  # Large payload
        packet = IP(dst=self.target_ip)/UDP(dport=self.target_port)/payload
        fragments = fragment(packet, fragsize = self.frag_size)
        for frag in fragments:
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
        target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1')
        target_port=(job['target_port'] if 'target_port' in job else 13000)
        payload_size=(job['payload_size'] if 'payload_size' in job else 5000)
        frag_size=(job['frag_size'] if 'frag_size' in job else 500)
        return FragmentedPacketsInjector(tag, duration_ms, target_ip, target_port, payload_size, frag_size)



class MalformedPacketsInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, target_ip: str = "127.0.0.1", target_port: int = 13000):
        super().__init__(tag, duration_ms, target_ip, target_port)
        self.chosen_method = self.malformed_packets

    def malformed_packets(self, num_packets=80):
        """
        Send malformed packets to the target.
        """
        end_time = time.time() + (self.duration_ms / 1000)
        print(f"[{self.tag}] Sending malformed packets to  {self.target_ip}/{self.target_port}")
        while time.time() < end_time:
            # Example 1: Invalid TCP flag combination (SYN + FIN)
            packet1 = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags="SF")  # SYN+FIN
            
            # Example 2: Corrupted TCP sequence number
            packet2 = IP(dst=self.target_ip)/TCP(dport=self.target_port, seq=42949672)  # Invalid seq number

            # Example 3: Invalid IP version
            packet3 = IP(dst=self.target_ip, version=6)/TCP(dport=self.target_port)  # Force IPv6 version in IPv4 packet

            invalidPackets = {
                "SYN+FIN": packet1,
                "InvalidSeq": packet2,
                "InvalidIPVersion": packet3
            }
            packetType = random.choice(list(invalidPackets.keys()))   
            #print(f"chosen invalid packet: {packetType}")  
            send(invalidPackets[packetType], verbose=False)

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
        target_port=(job['target_port'] if 'target_port' in job else 13000)
        return MalformedPacketsInjector(tag, duration_ms, target_ip, target_port)
        



class ProtocolAnomaliesInjector(NetworkLoadInjector):
    def __init__(self, tag: str = '', duration_ms: float = 1000, target_ip: str = "127.0.0.1", target_port: int = 13000):
        super().__init__(tag, duration_ms, target_ip)
        self.chosen_method = self.protocol_anomalies
    
    def protocol_anomalies(self, num_packets=80):
        """
        Send unexpected protocol packets to the target.
        """
        print(f"[{self.tag}] Sending protocol anomalies to  {self.target_ip}/{self.target_port}")
        for _ in range(num_packets):
            # Send ICMP Echo packets (ping packets basically)
            packet = IP(dst=self.target_ip)/ICMP()
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
        target_port=(job['target_port'] if 'target_port' in job else 13000)
        return ProtocolAnomaliesInjector(tag, duration_ms, target_ip, target_port)
    
            
             

 
""" 
def pack_flooding():
        
        Simulate packet flooding by sending many SYN packets to a single port.
        
        #print(f"[{self.tag}] Starting packet flooding on {self.target_ip}/{self.target_port}")
        end_time = time.time() + (5000 / 1000)
        while time.time() < end_time:
            packet = IP(dst="127.0.0.1")/TCP(dport=13000, flags="S")
            send(packet, verbose=False)



def malf_packets(target_ip, target_port, num_times=10):
    
    Send malformed packets to the target.
    
    for _ in range(num_times):
        # Example 1: Invalid TCP flag combination (SYN + FIN)
        packet1 = IP(dst=target_ip)/TCP(dport=target_port, flags="SF")  # SYN+FIN
        
        # Example 2: Corrupted TCP sequence number
        packet2 = IP(dst=target_ip)/TCP(dport=target_port, seq=42949672)  # Invalid seq number

        # Example 3: Invalid IP version
        packet3 = IP(dst=target_ip, version=6)/TCP(dport=target_port)  # Force IPv6 version in IPv4 packet

        invalidPackets = {
            "SYN+FIN": packet1,
            "InvalidSeq": packet2,
            "InvalidIPVersion": packet3
        }
        packetType = random.choice(list(invalidPackets.keys()))   
        #print(f"chosen invalid packet: {packetType}")  
        send(invalidPackets[packetType], verbose=False)
        

if __name__ == "__main__":
    interf = show_interfaces()
    print(interf)
    payload = "X" * 1021
    packet = IP(dst="127.0.0.1")/TCP(dport=13001)/payload
    send(packet, verbose=True) 
    #pack_flooding()
    malf_packets("127.0.0.1", 13000, num_times=10) 
"""