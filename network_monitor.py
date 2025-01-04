import csv
import pyshark
from datetime import datetime
import time

def current_milli_time():
    return round(time.time() * 1000)

def capture_and_save_network_traffic(interface, typeOfAnalysis = "normal", timeout = 5, output_file = "output/network_traffic.csv"):
    is_first_time = True
    print(f"Starting capture on interface: {interface}")
    capture = pyshark.LiveCapture(interface=interface, bpf_filter ="dst host 192.168.1.8")
    capture.sniff(timeout=timeout)
    capture.close()
    length = len(capture) #we have to save this before since the close() method doesnt really stop the capturing, if i do not save the length beforehand the loop will likely run indefinetely

    packet_data = []
    print("Captured packets:")
    for i in range(length):
        try:
            pkt = capture[i]
            packet_info = {
                "time": current_milli_time(),
                "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "sniff_timestamp": pkt.sniff_timestamp if hasattr(pkt, 'sniff_timestamp') else "Unknown",
                "protocol": pkt.highest_layer,
                "transport_layer": pkt.transport_layer if hasattr(pkt, 'transport_layer') else "Unknown",
                "src_ip": pkt.ip.src if hasattr(pkt, 'ip') else "Unknown",
                "dst_ip": pkt.ip.dst if hasattr(pkt, 'ip') else "Unknown",
                "packet_length": int(pkt.length),
                "header_length": int(pkt[pkt.transport_layer].hdr_len) if pkt.transport_layer in pkt else "Unknown",
                "checksum": pkt[pkt.transport_layer].checksum if pkt.transport_layer in pkt else "Unknown",
                "src_port": pkt[pkt.transport_layer].srcport if pkt.transport_layer in pkt else "Unknown",
                "dst_port": pkt[pkt.transport_layer].dstport if pkt.transport_layer in pkt else "Unknown",
                "seq_number": pkt[pkt.transport_layer].seq if pkt.transport_layer in pkt else "Unknown",
                "ack_number": pkt[pkt.transport_layer].ack if pkt.transport_layer in pkt else "Unknown",
                "time_relative": pkt[pkt.transport_layer].time_relative if pkt.transport_layer in pkt else "Unknown",
                "time_delta": pkt[pkt.transport_layer].time_delta if pkt.transport_layer in pkt else "Unknown",
                "time_to_live": pkt.ip.ttl if hasattr(pkt, 'ip') else "Unknown",
                "flags": pkt[pkt.transport_layer].flags if pkt.transport_layer in pkt else "Unknown", 
            }
            
            packet_info["label"] = "normal" if(typeOfAnalysis == "normal") else "anomalous"
            
            print(str(packet_info) + "\n")
            write_to_csv(output_file, packet_info, is_first_time)
            is_first_time = False
            packet_data.append(packet_info)
        except AttributeError as e:
            print(f"Error parsing packet: {e}")
            continue  # Skip packets with missing attributes

    return packet_data


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



def write_to_csv(filename, data, is_first_time):
    with open(filename, 'a' if not is_first_time else 'w', newline="") as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        if is_first_time:
            writer.writeheader()
        writer.writerow(data)

if __name__ == "__main__":
    output_file = "output/network_traffic.csv"
    is_first_time = True
    interfaces = ["Wi-Fi", "Adapter for loopback traffic capture"]  # Replace with the correct interface name
    intervals = {"normal": 10, "PortScanning": 5, "PacketFlooding": 5, "IPSpoofing": 5, "OversizedPackets": 5, "FragmentedPackets": 5, "MalformedPackets": 5, "ProtocolAnomalies": 5}
    for interval_type, time in intervals.items():
        print("Capturing traffic...")
        traffic_data = capture_and_save_network_traffic(interface=interfaces, timeout = time, outputfile=output_file)
        print("im here\n\n")
        
        start = time.time()
        normal_end_time = start + 10
        
