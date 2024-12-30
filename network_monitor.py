import csv
import pyshark
from datetime import datetime
import time

def current_milli_time():
    return round(time.time() * 1000)

def capture_and_save_network_traffic(interface, duration, outputfile):
    is_first_time = True
    print(f"Starting capture on interface: {interface}")
    capture = pyshark.LiveCapture(interface=interface, bfp_filter="tcp.port == 13000")
    capture.sniff(timeout=duration)
    capture.close()

    packet_data = []
    print("Captured packets:")
    for pkt in capture:
        try:
            packet_info = {
                "time": current_milli_time(),
                "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "protocol": pkt.highest_layer,
                "transport_layer": pkt.transport_layer if hasattr(pkt, 'transport_layer') else "Unknown",
                "src_ip": pkt.ip.src if hasattr(pkt, 'ip') else "Unknown",
                "dst_ip": pkt.ip.dst if hasattr(pkt, 'ip') else "Unknown",
                "packet_size": int(pkt.length),
                "src_port": pkt[pkt.transport_layer].srcport if pkt.transport_layer in pkt else "Unknown",
                "dst_port": pkt[pkt.transport_layer].dstport if pkt.transport_layer in pkt else "Unknown"
            }
            print(str(packet_info) + "\n")
            write_to_csv(output_file, packet_info, is_first_time)
            is_first_time = False
            packet_data.append(packet_info)
        except AttributeError as e:
            print(f"Error parsing packet: {e}")
            continue  # Skip packets with missing attributes

    return packet_data

def write_to_csv(filename, data, is_first_time):
    with open(filename, 'a' if not is_first_time else 'w', newline="") as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        if is_first_time:
            writer.writeheader()
        writer.writerow(data)

if __name__ == "__main__":
    output_file = "network_traffic.csv"
    is_first_time = True
    interface_name = "Wi-Fi"  # Replace with the correct interface name
    while True:
        print("Capturing traffic...")
        traffic_data = capture_and_save_network_traffic(interface=interface_name, duration=10, outputfile=output_file)
        """ if traffic_data:
            write_to_csv(output_file, traffic_data, is_first_time)
            is_first_time = False
            print(f"Captured {len(traffic_data)} packets.")
        else:
            print("No packets captured.") """
