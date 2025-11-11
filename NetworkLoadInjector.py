import random
import threading
import time

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
    UDP
)
from scapy.all import send, fragment, Raw
from scapy.all import (
    IP,      # Internet Protocol v4
    ARP,     # Address Resolution Protocol
    ICMP    # Internet Control Message Protocol
)
import random
import time

L4_PROTOCOLS = [UDP, TCP]
L3_PROTOCOLS = [IP, ARP, ICMP]


class NetworkLoadInjector(LoadInjector):
    """
    Base class for network attack simulations.
    Supports:
    - Configurable target IP/port
    - Source IP spoofing
    - Duration control
    - Thread-based execution
    """

    def __init__(self, tag: str = '', duration_ms: float = 5000, source_ip: str = None, target_ip: str = "127.0.0.1", target_port: int = 80):
        """
        Constructor for NetworkTrafficInjection
        :param tag: Tag for the injector
        :param duration_ms: Duration of the injection in milliseconds
        :param target_ip: Target IP for the injection
        """
        super().__init__(tag, duration_ms)
        self.target_ip = target_ip
        self.target_port = target_port
        self.source_ip = source_ip
        self.chosen_method = None
        
        
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
                elif job['type'] == "OversizedPacketsInjection":
                    return OversizedPacketsInjector.fromJSON(job)
                elif job['type'] == "FragmentedPacketsInjection":
                    return FragmentedPacketsInjector.fromJSON(job)
                elif job['type'] == "MalformedPacketsInjection":
                    return MalformedPacketsInjector.fromJSON(job)
        return None

        
           
        
# INJECTOR IMPLEMENTATIONS        

class PortScanningInjector(NetworkLoadInjector):
    """
    Port scanning attack simulation.
    Features:
    - Sequential port scanning
    - Random protocol selection (TCP/UDP)
    - TCP flag manipulation
    - Source IP spoofing
    """
    def __init__(self, tag: str = '', duration_ms: float = 1000, source_ip:str = None, target_ip: str = "127.0.0.1"):
        super().__init__(tag, duration_ms, source_ip, target_ip)
        self.chosen_method = self.port_scanning
    
    def port_scanning(self):
        """
        Simulate port scanning by sending TCP/UDP scanning packets to all possible ports in the duration time
        """
        end_time = time.time() + (self.duration_ms / 1000)
        print(f"[{self.tag}] Starting port scanning on {self.target_ip}/{self.target_port}")
        
        port = 0
        while time.time() < end_time:  # Scan ports 1-1024
            
            #defining a random source ip if its not defined
            src_ip = random_ip() if(self.source_ip==None) else self.source_ip
            
            #choosing one between tcp and udp
            l4_protocol = random.choice(L4_PROTOCOLS)
            
            #if the protocol chosen is tcp then i add the flags transp.layer flags to the packet(randomly chosen)
            if l4_protocol is TCP:
                packet = IP(src=src_ip, dst=self.target_ip)/l4_protocol(sport = random.randint(1, 60000), dport=port, flags=random.choice(['S','A','F']))
            else:
                packet = IP(src=src_ip, dst=self.target_ip)/l4_protocol(sport = random.randint(1, 60000), dport=port)
            
            #sending packet at layer 3 with scapy's send function
            send(packet,   verbose=False)
            port += 1
        
    def get_name(self) -> str:
        """
        Returns a descriptive name for the injector.
        """
        return f"[{self.tag}]{self.__class__.__name__}(duration: {self.duration_ms})"
    
    @classmethod
    def fromJSON(cls, job):   
        return cls(
            tag=(job['tag'] if 'tag' in job else ''),
            duration_ms=(job['duration_ms'] if 'duration_ms' in job else 1000),
            source_ip = (job['source_ip'] if 'source_ip' in job else None),
            target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1')
        )


class PacketFloodingInjector(NetworkLoadInjector):
    """
    DoS-style packet flooding.
    Features:
    - High-rate packet generation
    - Random/fixed target ports
    - UDP flood implementation
    - Configurable packet rate
    """
    def __init__(self, tag: str = '', duration_ms: float = 1000, source_ip:str = None, target_ip: str = "127.0.0.1", target_port: int = 80):
        super().__init__(tag, duration_ms, source_ip, target_ip, target_port)
        self.chosen_method = self.packet_flooding
   
    def packet_flooding(self):
        """
        Simulate packet flooding by sending many UDP packets to different or a single targeted port
        """
        print(f"[{self.tag}] Starting packet flooding on {self.target_ip}/{self.target_port}")
        end_time = time.time() + (self.duration_ms / 1000)
        
        src_ip = random_ip() if(self.source_ip==None) else self.source_ip
        
        while time.time() < end_time:
            packet = IP(src=src_ip, dst=self.target_ip)/UDP(sport = random.randint(1, 60000), dport=(random.randint(1,60000) if(self.target_port==None) else self.target_port))
            send(packet,  verbose=False)
    
    def get_name(self) -> str:
        """
        Returns a descriptive name for the injector.
        """
        return f"[{self.tag}]{self.__class__.__name__}(duration: {self.duration_ms})"
    
    @classmethod
    def fromJSON(cls, job):
        return cls(
            tag=(job['tag'] if 'tag' in job else ''),
            duration_ms=(job['duration_ms'] if 'duration_ms' in job else 1000),
            source_ip = (job['source_ip'] if 'source_ip' in job else None),
            target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1'),
            target_port=(job['target_port'] if 'target_port' in job else 80)
        )



class OversizedPacketsInjector(NetworkLoadInjector):
    """
    Buffer overflow testing via large packets.
    Features:
    - Configurable payload size
    - Random protocol selection
    - Raw payload injection
    """
    def __init__(self, tag: str = '', duration_ms: float = 1000, source_ip:str = None, target_ip: str = "127.0.0.1", target_port: int = 80, size:int = 1000):
        super().__init__(tag, duration_ms, source_ip, target_ip, target_port)
        self.chosen_method = self.oversized_packets
        self.size = size
            
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
            packet = IP(src=src_ip, dst=self.target_ip)/l4_protocol(sport = random.randint(1, 60000), dport = self.target_port)/Raw(load = payload) 
            
            send(packet, verbose=False)        
    
    def get_name(self) -> str:
        """
        Returns a descriptive name for the injector.
        """
        return f"[{self.tag}]{self.__class__.__name__}(duration: {self.duration_ms})"
    
    @classmethod
    def fromJSON(cls, job):
        return cls(
            tag=(job['tag'] if 'tag' in job else ''),
            duration_ms=(job['duration_ms'] if 'duration_ms' in job else 1000),
            source_ip = (job['source_ip'] if 'source_ip' in job else None),
            target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1'),
            target_port=(job['target_port'] if 'target_port' in job else 80),
            size=(job['size'] if 'size' in job else 2000)
        )



class FragmentedPacketsInjector(NetworkLoadInjector):
    """
    IP fragmentation attack simulation.
    Features:
    - Custom fragment sizes
    - Payload fragmentation
    - Protocol-aware splitting
    - Fragment ordering
    """
    def __init__(self, tag: str = '', duration_ms: float = 1000, source_ip: str = None, target_ip: str = "127.0.0.1", target_port: int = 80, payload_size:int = 500, frag_size:int = 50):
        super().__init__(tag, duration_ms, source_ip, target_ip, target_port)
        self.chosen_method = self.fragmented_packets
        self.payload_size = payload_size
        self.frag_size = frag_size
        
    def fragmented_packets(self):
        """
        Send fragmented packets to the target.
        """
        print(f"[{self.tag}] Sending fragmented packets to  {self.target_ip}/{self.target_port}")
        end_time = time.time() + (self.duration_ms / 1000)
        
        while time.time() < end_time: 
            #defining a random source ip if its not defined
            src_ip = random_ip() if(self.source_ip==None) else self.source_ip
            
            #choosing the layer 4 protocol randomly
            l4_protocol = random.choice(L4_PROTOCOLS)
            
            #creating the packet to fragment
            payload = "A" * self.payload_size
            packet = IP(src=src_ip, dst=self.target_ip)/l4_protocol(sport = random.randint(1, 60000), dport=(random.randint(1,60000) if(self.target_port==None) else self.target_port))/Raw(load = payload)
            
            #fragmenting it with scapy's fragment function
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
        return cls(
            tag=(job['tag'] if 'tag' in job else ''),
            duration_ms=(job['duration_ms'] if 'duration_ms' in job else 1000),
            source_ip = (job['source_ip'] if 'source_ip' in job else None),
            target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1'),
            target_port=(job['target_port'] if 'target_port' in job else 80),
            payload_size=(job['payload_size'] if 'payload_size' in job else 500),
            frag_size=(job['frag_size'] if 'frag_size' in job else 50),
        )





class MalformedPacketsInjector(NetworkLoadInjector):
    """
    Protocol violation testing.
    Features:
    - Invalid TCP flags
    - Sequence number manipulation
    - Acknowledgment number manipulation
    - Header field corruption
    """
    def __init__(self, tag: str = '', duration_ms: float = 1000, source_ip:str = None, target_ip: str = "127.0.0.1", target_port: int = 80):
        super().__init__(tag, duration_ms, source_ip, target_ip, target_port)
        self.chosen_method = self.malformed_packets

    def malformed_packets(self):
        """
        Send malformed packets to the target.
        """
        print(f"[{self.tag}] Sending malformed packets to  {self.target_ip}/{self.target_port}")
        
        end_time = time.time() + (self.duration_ms / 1000)
        while time.time() < end_time:
    
            #defining a random source ip if its not defined
            src_ip = random_ip() if(self.source_ip==None) else self.source_ip
            
            # Example: Invalid TCP flag values, seq value, ack value etc.
            packet = IP(src=src_ip, dst=self.target_ip)/TCP(sport = random.randint(1, 60000), dport=(random.randint(1,60000) if(self.target_port==None) else self.target_port), flags=random.randint(0,999), seq=random.randint(1000000, 4294967295),  ack=random.randint(100000,4294967295))

            send(packet, verbose=False)

    def get_name(self) -> str:
        """
        Returns a descriptive name for the injector.
        """
        return f"[{self.tag}]{self.__class__.__name__}(duration: {self.duration_ms})"

    @classmethod
    def fromJSON(cls, job):
        return cls(
            tag=(job['tag'] if 'tag' in job else ''),
            duration_ms=(job['duration_ms'] if 'duration_ms' in job else 1000),
            source_ip = (job['source_ip'] if 'source_ip' in job else None),
            target_ip=(job['target_ip'] if 'target_ip' in job else '127.0.0.1'),
            target_port=(job['target_port'] if 'target_port' in job else 80)
        )