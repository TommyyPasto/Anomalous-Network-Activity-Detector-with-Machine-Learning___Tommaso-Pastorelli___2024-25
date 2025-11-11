import time
from sklearn.utils import shuffle
import joblib
import pyshark
from datetime import datetime
import time
import pandas as pd
import sys


def current_ms():
    """Returns current time in milliseconds"""
    return round(time.time() * 1000)

def from_hex_to_int(string):
    """
    Convert hexadecimal string to integer
    Args:
        string: Hex string (e.g., '0x00')
    Returns:
        Integer value or -1 if conversion fails
    """
    if string == None:
        return None
    else:
        try:
            integer = int(string, 16)
            return integer
        except Exception:
            return 0

def process_live_packet(pkt):
    """
    Extract features from live captured packet
    
    Features:
    - Layer 3: IP headers, flags, length
    - Layer 4: Transport protocol details
    - Timing: Timestamps and deltas
    - Custom: Fragmentation detection
    
    Args:
        pkt: pyshark packet object
    Returns:
        DataFrame with packet features or None if error
    """
    try:
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
        return pd.DataFrame([packet_info])
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None


def live_predict(model_path, output_path, interface="Wi-Fi", duration="endless"):
    """
    Real-time packet capture and anomaly detection
    
    Args:
        model_path: Path to trained model file
        output_path: CSV file for predictions
        interface: Network interface(s) to monitor
        duration: Monitoring duration in seconds or "endless"
    """
    # Load model
    model = joblib.load(model_path)
    
    # Defining the Live capture
    capture = pyshark.LiveCapture(interface=interface, bpf_filter="dst 192.168.1.16")
    print(f"Starting capture on {interface} for {duration} seconds...")
    
    #add the header
    with open(output_path, "w") as f:
        f.write("time,datetime,sniff_timestamp,protocol,transport_layer,src_ip,dst_ip,packet_length,header_length,ip_flags,time_to_live,time_relative,time_delta,is_fragmented,checksum,src_port,dst_port,seq_number,ack_number,flags,label\n")
             
    
    start_time = time.time()
    while time.time() - start_time < duration if type(duration) is int else True:
        try:
            # Starting the live sniffing and parsing of packets
            for packet in capture.sniff_continuously():
                if(type(duration) is int and time.time() - start_time >= duration):
                    break
                if(hasattr(packet, "ip") == False):
                    continue
               
                # Process packet
                df_packet = process_live_packet(packet)
                if df_packet is not None:
                    
                    # Prepare for prediction
                    df_packet["checksum"] = df_packet["checksum"].apply(from_hex_to_int)
                    df_packet["flags"] = df_packet["flags"].apply(from_hex_to_int)
                    df_packet["ip_flags"] = df_packet["ip_flags"].apply(from_hex_to_int)
                    
                    # Drop unnecessary columns
                    features = df_packet.drop(columns=["time", "datetime", "time_relative", "sniff_timestamp", "src_ip", "dst_ip","transport_layer"])
                    
                    # Predict
                    prediction = model.predict(features)[0]
                    df_packet['predicted_label'] = prediction
                           
                    # Append to file
                    df_packet.to_csv(output_path, mode='a', header=False, index=False)
                    print(f"Packet processed - Prediction: {prediction}")
                    
        except Exception:
            break
    
    capture.close()
    print("Capture complete")




if __name__ == "__main__":
    
    MODEL_PATH = "./training_results/packet_detector_model.pkl"
    
    args = sys.argv
   
    if len(args) == 1:
        print("execution time was set to: endless")
        exe_time = "endless"
    else:
        print(f"execution time was set at default value: {args[1]} seconds")
        exe_time = int(args[1])
    
    # Start live prediction
    live_predict(
        model_path=MODEL_PATH,
        output_path = "./LiveDetection/predictions.csv",
        interface=["Wi-Fi","Adapter for loopback traffic capture"],
        duration=exe_time
    )