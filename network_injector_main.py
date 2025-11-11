import csv
import os
import random
import time
import json
from tqdm import tqdm
from NetworkLoadInjector import *
import sys


def sequential_injector(injectors: list, verbose: bool = True):
    """
    Sequentially executes each injector for dataset collection.
    Each injection completes before starting the next one.
    
    Args:
        injectors: List of NetworkLoadInjector objects
        verbose: Enable logging
    Returns:
        list: Timestamps and details of all injections
    """

    activations = []
    if injectors is not None and len(injectors) > 0:
        for inj_index in tqdm(range(len(injectors)), desc='Injector Progress Bar'):
           
            current_inj = injectors[inj_index]

            if not current_inj.is_injector_running():
                if verbose:
                    print("Injecting with injector '%s'" % current_inj.get_name())

                # Starts the injection thread
                thread = current_inj.inject()
                thread.join() #we wait for it to end injection

    else:
        print("No injectors were set for this experimental campaign")

    activations = []
    for inj in injectors:
        inj_log = inj.get_injections()
        if inj_log is not None and len(inj_log) > 0:
            new_inj = [dict(item, inj_name=inj.get_name()) for item in inj_log]
            activations.extend(new_inj)
            if verbose:
                print("Injections with injector '" + str(inj.get_name()) + "': " + str(len(new_inj)))

    return activations



def main_injector(max_n_obs: int, injectors: list, obs_interval_sec: int = 1, inj_duration_sec: int = 1,
                  inj_cooldown_sec: int = 2, inj_probability: float = 0.2, verbose: bool = True):
    """
    Main injection controller with randomized activation.
    
    Key Features:
    - Random injection selection
    - Cooldown periods between injections
    - Probability-based activation
    - Time-based synchronization
    
    Args:
        max_n_obs: Maximum observation cycles
        injectors: List of available injectors
        obs_interval_sec: Interval between observations
        inj_duration_sec: Duration of each injection
        inj_cooldown_sec: Mandatory wait time after injection
        inj_probability: Chance of injection per cycle (0.0-1.0)
        verbose: Enable detailed logging
    """

    # Injection Loop
    print('Injector Started. Active for %d times' % max_n_obs)
    current_inj = None
    inj_timer = 0
    cycle_ms = obs_interval_sec * 1000

    if injectors is not None and len(injectors) > 0:

        for obs_id in tqdm(range(max_n_obs), desc='Injector Progress Bar'):
            start_ms = current_ms()
            
            # If there are no active injections and no cooldown
            # If there is enough time before end of campaign
            # If probability activates
            if current_inj is None and inj_timer == 0 \
                    and ((max_n_obs - obs_id - 1) * cycle_ms > inj_duration_sec) \
                    and (random.randint(0, 999) / 999.0) <= inj_probability:

                # Randomly chooses an injector and performs injection
                while current_inj is None:
                    inj_index = random.randint(0, len(injectors) - 1)
                    if not injectors[inj_index].is_injector_running():
                        current_inj = injectors[inj_index]
                if verbose:
                    print("Injecting with injector '%s'" % current_inj.get_name())

                # Starts the injection thread
                current_inj.inject()
                inj_timer = inj_duration_sec + inj_cooldown_sec

            # Sleep to synchronize with cycle time
            sleep_s = (cycle_ms - (current_ms() - start_ms)) / 1000.0
            if sleep_s > 0:
                time.sleep(sleep_s)

            # Managing cooldown
            inj_timer = inj_timer - cycle_ms if inj_timer > 0 else 0
            if inj_timer < inj_cooldown_sec:
                current_inj = None

    else:
        print("No injectors were set for this experimental campaign")

    activations = []
    for inj in injectors:
        inj_log = inj.get_injections()
        if inj_log is not None and len(inj_log) > 0:
            new_inj = [dict(item, inj_name=inj.get_name()) for item in inj_log]
            activations.extend(new_inj)
            if verbose:
                print("Injections with injector '" + str(inj.get_name()) + "': " + str(len(new_inj)))

    return activations




def read_injectors(json_object, inj_duration = None, verbose: bool = True):
    """
    Parses injector configurations from JSON.
    Supports multiple injector types:
    - PortScanning
    - PacketFlooding
    - OversizedPackets
    - FragmentedPackets
    - MalformedPackets
    
    Args:
        json_object: JSON string or file path
        inj_duration: Override injection duration (ms)
        verbose: Enable detailed logging
    """
    try:
        json_object = json.loads(json_object)
    except ValueError:
        if os.path.exists(json_object):
            with open(json_object) as f:
                json_object = json.load(f)
        else:
            print(f"Could not parse input {json_object}")
            json_object = None

    injectors = []
    if json_object:
        for job in json_object:
            if inj_duration != None:
                job["duration_ms"] = inj_duration
            if job['type'] == 'PortScanningInjector':
                new_inj = PortScanningInjector.fromJSON(job)
            elif job['type'] == 'PacketFloodingInjector':
                new_inj = PacketFloodingInjector.fromJSON(job)
            elif job['type'] == 'OversizedPacketsInjector':
                new_inj = OversizedPacketsInjector.fromJSON(job)
            elif job['type'] == 'FragmentedPacketsInjector':
                new_inj = FragmentedPacketsInjector.fromJSON(job)
            elif job['type'] == 'MalformedPacketsInjector':
                new_inj = MalformedPacketsInjector.fromJSON(job)
            else:
                new_inj = NetworkLoadInjector.fromJSON(job)
            if new_inj and new_inj.is_valid():
                injectors.append(new_inj)
                if verbose:
                    print(f"New injector loaded from JSON: {new_inj.get_name()}")

    return injectors



def stop_execution():
    print("Stopping injector and monitor threads.")
    os._exit(0)



if __name__ == "__main__":
    """
    Entry point for the Injector
    """
    # Configuration constants
    out_folder = 'output_folder'     # Output directory for logs
    inj_filename = 'inj_info.csv'    # Injection event log file
    inj_duration_sec = 5             # Default injection duration
    inj_json = './input/injectors.json'  # Injector configurations
    
    args = sys.argv
   
    if len(args) == 1:
        print("execution time was set to: endless")
        exe_time = 20
    else:
        print(f"execution time was set at default value: {args[1]} seconds")
        exe_time = int(args[1])
       

    # Extracting definitions of injectors from input JSON
    injectors = read_injectors(inj_json) #pass inj_duration_sec if you want to override the duration value

    try:
        # Calling injection routine
        inj_timestamps = main_injector(max_n_obs=exe_time,
                                    injectors=injectors,
                                    obs_interval_sec=1,
                                    inj_duration_sec=inj_duration_sec,
                                    inj_cooldown_sec=1,
                                    inj_probability=0.8,
                                    verbose=True)
                        
        #this was used for generating anomalies in an easier way:            
        #inj_timestamps = sequential_injector(injectors=injectors)

        # Ensure output folder exists
        if not os.path.exists(out_folder):
            os.mkdir(out_folder)

        # Save injection logs to CSV
        inj_filename = os.path.join(out_folder, inj_filename)
        with open(inj_filename, 'w', newline='') as myFile:
            writer = csv.writer(myFile)
            keys = ['start', 'end', 'inj_name']
            writer.writerow(keys)
            for dictionary in inj_timestamps:
                writer.writerow([str(dictionary[d_key]) for d_key in keys])
                
    except KeyboardInterrupt:
        stop_execution()
        
        
