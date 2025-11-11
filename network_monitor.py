import csv
import pyshark
from datetime import datetime
import time
from pynput import keyboard
import sys



def current_ms():
    return round(time.time() * 1000)

def process_packet(pkt):
    """
    Extracts relevant features from captured packets for anomaly detection.
    
    Args:
        pkt: Pyshark packet object
    Returns:
        dict: Dictionary containing packet features
    """
    
    packet_info = {
        #general layer 3 level features
        "time": current_ms(),
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "sniff_timestamp": pkt.sniff_timestamp if hasattr(pkt, 'sniff_timestamp') else 0,
        "protocol": pkt.ip.proto if hasattr(pkt, 'ip') else 0,
        "transport_layer": pkt.transport_layer if hasattr(pkt, 'transport_layer') else 0,
        "src_ip": pkt.ip.src if hasattr(pkt, 'ip') else 0,
        "dst_ip": pkt.ip.dst if hasattr(pkt, 'ip') else 0,
        "packet_length": int(pkt.length) if hasattr(pkt, 'length') else 0,
        "header_length": pkt.ip.hdr_len if hasattr(pkt.ip,"hdr_len") else 0,
        "ip_flags": pkt.ip.flags,
        "time_to_live": pkt.ip.ttl if hasattr(pkt, 'ip') else 0,
        "time_relative": pkt.frame_info.time_relative if hasattr(pkt.frame_info,"time_relative") else 0,
        "time_delta": pkt.frame_info.time_delta if hasattr(pkt.frame_info, "time_delta") else 0,
        
        #derived feature that aimes to help the model to distinguish better between fragmented and not frag. pkts
        "is_fragmented": 1 if(pkt.ip.flags == "0x01" or pkt.ip.flags == "0x00") and pkt.transport_layer is None else 0, 
        
        #transport layer(layer 4) features(not filled when a fragmented packet injection is performed since only the first fragment has t.layer infos)
        "checksum": pkt[pkt.transport_layer].checksum if(pkt.transport_layer is not None and hasattr(pkt[pkt.transport_layer], 'checksum')) else 0,
        "src_port": pkt[pkt.transport_layer].srcport if(pkt.transport_layer is not None and hasattr(pkt[pkt.transport_layer], 'srcport')) else 0,
        "dst_port": pkt[pkt.transport_layer].dstport if(pkt.transport_layer is not None and hasattr(pkt[pkt.transport_layer], "dstport")) else 0,
        "seq_number": pkt[pkt.transport_layer].seq if pkt.transport_layer is not None and hasattr(pkt[pkt.transport_layer], "seq") else 0,
        "ack_number": pkt[pkt.transport_layer].ack if pkt.transport_layer is not None and hasattr(pkt[pkt.transport_layer], "ack") else 0,
        "flags": pkt[pkt.transport_layer].flags if pkt.transport_layer is not None and  hasattr(pkt[pkt.transport_layer],"flags") else "0x00",
    }
    return packet_info
    
    
    
#defining a way to esc the monitoring pressing esc   
stop_capture = False

def on_press(key):
    global stop_capture
    if key == keyboard.Key.ctrl:
        stop_capture = True
        return False

#Function for capturing data on "interface", with "timeout"
def capture_traffic_data(interface, typeOfAnalysis, timeout) -> list:
    """
    Captures network traffic on specified interfaces with timeout/ESC control.
    
    Args:
        interface: Network interface(s) to monitor
        typeOfAnalysis: 'normal' or 'anomalous' - labels for captured traffic
        timeout: Integer for timed capture or "endless" for manual stop
    
    Returns:
        list: List of processed packet dictionaries
    """
    
    #defining a way to stop capture halfway
    global stop_capture
    stop_capture = False
    
    # Start keyboard listener in separate thread
    listener = keyboard.Listener(on_press=on_press)
    listener.start()

    print(f"Starting capture on interface: {interface}")
    capture = pyshark.LiveCapture(interface=interfaces, bpf_filter="dst 192.168.1.16")
    
    if type(timeout) == int:
        end_time = time.time() + timeout
    
    packet_data = []
    
    print("Press ESC to stop capture...")

    # Process packets until ESC pressed
    while (time.time() < end_time and not stop_capture) if type(timeout) is int else not stop_capture:
        for pkt in capture.sniff_continuously():
            try:
                packet_info = process_packet(pkt)
            
                packet_info["label"] = "normal" if(typeOfAnalysis == "normal") else "anomalous"
                
                print(str(packet_info) + "\n")
                #pkt.pretty_print()
                print("-----------------------------------------------\n\n\n")
                packet_data.append(packet_info)
                
            except AttributeError as e:
                print(f"Error parsing packet: {e}")
                continue  # Skip packets with missing attributes
            if(type(timeout) is int and time.time() >= end_time):
                break
            if(stop_capture):
                break
    capture.close()
    listener.stop()
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
    output_file = "./output_folder/monitoring_results.csv"
    interfaces = ["Wi-Fi", "Adapter for loopback traffic capture"] 
    
    args = sys.argv
    
    if len(args) == 1:
        print("execution time was set to: endless")
        timeout = "endless"
    else:
        print(f"execution time was set at default value: {args[1]} seconds")
        timeout = int(args[1])
        
        #                                                    set this value manually when collecting data
        #                                                                        |
    try:#                                                                        V
        packets_data = capture_traffic_data(interface=interfaces, typeOfAnalysis="anomalous", timeout=timeout)
        if(len(packets_data) > 0):
            write_to_csv(output_file, packets_data, is_first_time=True)
        else:
            print("no packets received")
            
    except KeyboardInterrupt:
        print("Stopping monitor thread.")
        exit(0)   
