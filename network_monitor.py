
"""TCP: {'tcp.srcport': '443', 'tcp.dstport': '60070', 'tcp.port': '443', 'tcp.stream': '0', 
            'tcp.completeness': '0', 'tcp.completeness.rst': 'False', 'tcp.completeness.fin': 'False', 
            'tcp.completeness.data': 'False', 'tcp.completeness.ack': 'False', 'tcp.completeness.syn-ack': 'False', 
            'tcp.completeness.syn': 'False', 'tcp.completeness.str': '[ Null ]', 'tcp.len': '0', 'tcp.seq': '0', 
            'tcp.seq_raw': '679767636', 'tcp.nxtseq': '1', 'tcp.ack': '1', 'tcp.ack_raw': '198280632', 'tcp.hdr_len': '32', 
            'tcp.flags': '0x0012', 'tcp.flags.res': 'False', 'tcp.flags.ae': 'False', 'tcp.flags.cwr': 'False', 
            'tcp.flags.ece': 'False', 'tcp.flags.urg': 'False', 'tcp.flags.ack': 'True', 'tcp.flags.push': 'False', 
            'tcp.flags.reset': 'False', 'tcp.flags.syn': 'True', '_ws.expert': 'Expert Info (Chat/Sequence): Connection establish acknowledge (SYN+ACK): server port 443', 
            'tcp.connection.synack': 'Connection establish acknowledge (SYN+ACK): server port 443', '_ws.expert.message': 'Connection establish acknowledge (SYN+ACK): server port 443', 
            '_ws.expert.severity': '2097152', '_ws.expert.group': '33554432', 'tcp.flags.fin': 'False', 
            'tcp.flags.str': '�������A��S�', 'tcp.window_size_value': '26883', 'tcp.window_size': '26883', 
            'tcp.checksum': '0xe207', 'tcp.checksum.status': '2', 'tcp.urgent_pointer': '0', 
            'tcp.options': '02:04:05:ac:01:01:04:02:01:03:03:08', 'tcp.options.mss': '02:04:05:ac', 'tcp.option_kind': '2', 
            'tcp.option_len': '4', 'tcp.options.mss_val': '1452', 'tcp.options.nop': '01', 'tcp.options.sack_perm': '04:02', 
            'tcp.options.wscale': '03:03:08', 'tcp.options.wscale.shift': '8', 'tcp.options.wscale.multiplier': '256', 
            '': 'Timestamps', 'tcp.time_relative': '0.000000000', 'tcp.time_delta': '0.000000000'}
            """


"""
packet_info = {
                "time": current_milli_time(),
                "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "sniff_timestamp": pkt.sniff_timestamp if hasattr(pkt, 'sniff_timestamp') else -1,
                "protocol": pkt.highest_layer if hasattr(pkt, 'highest_layer') else -1,
                "transport_layer": pkt.transport_layer if hasattr(pkt, 'transport_layer') else -1,
                "src_ip": pkt.ip.src if hasattr(pkt, 'ip') else -1,
                "dst_ip": pkt.ip.dst if hasattr(pkt, 'ip') else -1,
                "packet_length": int(pkt.length) if hasattr(pkt, 'length') else -1,
                "header_length": int(pkt[pkt.transport_layer].hdr_len) if hasattr(pkt.transport_layer,"hdr_len") else -1,
                "checksum": pkt[pkt.transport_layer].checksum if hasattr(pkt.transport_layer, 'checksum') else -1,
                "src_port": pkt[pkt.transport_layer].srcport if hasattr(pkt.transport_layer, 'srcport') else -1,
                "dst_port": pkt[pkt.transport_layer].dstport if hasattr(pkt.transport_layer, "dstport") else -1,
                "seq_number": pkt[pkt.transport_layer].seq if hasattr(pkt.transport_layer, "seq") else -1,
                "ack_number": pkt[pkt.transport_layer].ack if hasattr(pkt.transport_layer, "ack") else -1,
                "time_relative": pkt[pkt.transport_layer].time_relative if hasattr(pkt.transport_layer,"time_relative") else -1,
                "time_delta": pkt[pkt.transport_layer].time_delta if hasattr(pkt.transport_layer, "time_delta") else -1,
                "time_to_live": pkt.ip.ttl if hasattr(pkt, 'ip') else -1,
                "flags": pkt[pkt.transport_layer].flags if hasattr(pkt.transport_layer,"flags") else -1,
            }"""





import csv
import threading
import pyshark
from scapy.all import IP, TCP, UDP, ICMP, send, fragment, show_interfaces, Ether, ARP, srp1, conf, Raw, sniff, json
from datetime import datetime
import time

# Synchronization primitives
traffic_semaphore = threading.Semaphore(1)
injection_semaphore = threading.Semaphore(0)

def current_milli_time():
    return round(time.time() * 1000)


#Function for capturing data on "interface", with "timeout"
def capture_traffic_data(interface, typeOfAnalysis, timeout) -> list:
    is_first_time = True
    print(f"Starting capture on interface: {interface}")
    capture = pyshark.LiveCapture(interface=interfaces, bpf_filter="dst 192.168.1.8")
    #capture = sniff(iface="Software Loopback Interface 1", timeout=timeout)
    capture.sniff(timeout=timeout)
    capture.close()
    length = len(capture) #we have to save this before since the close() method doesnt really stop the capturing, if i do not save the length beforehand the loop will likely run indefinetely

    packet_data = []
    print("Captured packets:")
    for i in range(length):
        try:
            pkt = capture[i]
            packet_info = {
                
                #general layer 3 level features
                "time": current_milli_time(),
                "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "sniff_timestamp": pkt.sniff_timestamp if hasattr(pkt, 'sniff_timestamp') else -1,
                "protocol": pkt.ip.proto if hasattr(pkt, 'ip') else -1,
                "transport_layer": pkt.transport_layer if hasattr(pkt, 'transport_layer') else -1,
                "src_ip": pkt.ip.src if hasattr(pkt, 'ip') else -1,
                "dst_ip": pkt.ip.dst if hasattr(pkt, 'ip') else -1,
                "packet_length": int(pkt.length) if hasattr(pkt, 'length') else -1,
                "header_length": pkt.ip.hdr_len if hasattr(pkt.ip,"hdr_len") else -1,
                "ip_flags": pkt.ip.flags,
                "time_to_live": pkt.ip.ttl if hasattr(pkt, 'ip') else -1,
                "time_relative": pkt.frame_info.time_relative if hasattr(pkt.frame_info,"time_relative") else -1,
                "time_delta": pkt.frame_info.time_delta if hasattr(pkt.frame_info, "time_delta") else -1,
                
                #derived feature that aimes to help the model to distinguish better between fragmented and not frag. pkts
                "is_fragmented": 1 if(pkt.ip.flags == "0x01" or pkt.ip.flags == "0x00") and pkt.transport_layer is None else 0, 
                
                #transport layer(layer 4) features(not filled when a fragmented packet injection is performed since only the first fragment has t.layer infos)
                "checksum": pkt[pkt.transport_layer].checksum if(pkt.transport_layer is not None and hasattr(pkt[pkt.transport_layer], 'checksum')) else -1,
                "src_port": pkt[pkt.transport_layer].srcport if(pkt.transport_layer is not None and hasattr(pkt[pkt.transport_layer], 'srcport')) else -1,
                "dst_port": pkt[pkt.transport_layer].dstport if(pkt.transport_layer is not None and hasattr(pkt[pkt.transport_layer], "dstport")) else -1,
                "seq_number": pkt[pkt.transport_layer].seq if pkt.transport_layer is not None and hasattr(pkt[pkt.transport_layer], "seq") else -1,
                "ack_number": pkt[pkt.transport_layer].ack if pkt.transport_layer is not None and hasattr(pkt[pkt.transport_layer], "ack") else -1,
                "flags": pkt[pkt.transport_layer].flags if pkt.transport_layer is not None and  hasattr(pkt[pkt.transport_layer],"flags") else -1,
                
                #layer 7 features for dns packets(1 attack)
                "dns_query_type": pkt.dns.qry_type if hasattr(pkt, 'dns') else -1,
                "dns_query_name": pkt.dns.qry_name if hasattr(pkt, 'dns') else -1,
                "dns_response": pkt.dns.resp_name if hasattr(pkt, 'dns') else -1,
                "dns_ttl": pkt.dns.ttl if hasattr(pkt, 'dns') else -1,
            }
           
            packet_info["label"] = "normal" if(typeOfAnalysis == "normal") else "anomalous"
            
            print(str(packet_info) + "\n")
            #pkt.pretty_print()
            print("-----------------------------------------------\n\n\n")
            packet_data.append(packet_info)
            
        except AttributeError as e:
            print(f"Error parsing packet: {e}")
            continue  # Skip packets with missing attributes

    return packet_data


#utility function for writing data to csv
def write_to_csv(filename, data, is_first_time):
    with open(filename, 'a' if not is_first_time else 'w', newline="") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        if is_first_time:
            writer.writeheader()
        writer.writerows(data)




#main
if __name__ == "__main__":
    output_file = "output/copy.csv"
    interfaces = ["Adapter for loopback traffic capture"]  # Replace with your network interface
    
    from network_injector_main import read_injectors
    injectors = read_injectors("input/injectors_json.json", inj_duration=18000)
    try:
        
        """  packets_data = capture_and_save_network_traffic(interface=interfaces, typeOfAnalysis="normal", timeout=600)
        write_to_csv(output_file, packets_data, is_first_time=True) """
        
        for i in range(3):
            print("remaining time: " + str(3-i))
            time.sleep(1)
        
        # Capture anomalous traffic during injections
        packets_data = capture_traffic_data(interface=interfaces, typeOfAnalysis="anomalous", timeout=((3+2) * injectors.__len__()))
        write_to_csv(output_file, packets_data, is_first_time=False)
            
    except KeyboardInterrupt:
        print("Stopping monitor thread.")
        exit(0)   
