import csv
import os
import random
import time
import json
from tqdm import tqdm
import sys
#from NetworkLoadInjector import LoadInjector, current_ms
from NetworkLoadInjector import *

def main_injector(max_n_obs: int, injectors: list, obs_interval_sec: int = 1, inj_duration_sec: int = 1, randomize:bool = False,
                  inj_cooldown_sec: int = 2, verbose: bool = True):
    """
    Main function for monitoring
    :param inj_cooldown_sec: time to wait after an injection and before activating a new one (seconds)
    :param inj_duration_sec: duration of the injection (seconds)
    :param verbose: True if debug information has to be shown
    :param injectors: list of LoadInjector objects
    :param obs_interval_sec: seconds in between two observations (seconds)
    :param max_n_obs: maximum number of observations (no longer used)
    :return: list of dictionaries containing activations of injections
    """

    # Injection Loop
    print('Injector Started. Running for %d injectors' % len(injectors))
    cycle_ms = obs_interval_sec * 1000

    if injectors is not None and len(injectors) > 0:
        for inj_index in tqdm(range(len(injectors)), desc='Injector Progress Bar'):
            start_ms = current_ms()
            current_inj = injectors[inj_index]

            # Check if injector is not already running
            if not current_inj.is_injector_running():
                if verbose:
                    print("Injecting with injector '%s'" % current_inj.get_name())

                # Starts the injection thread
                current_inj.inject()

                # Wait for the injection duration
                time.sleep(inj_duration_sec)

                # Cooldown period
                time.sleep(inj_cooldown_sec)

            # Sleep to synchronize with cycle time
            sleep_s = (cycle_ms - (current_ms() - start_ms)) / 1000.0
            if sleep_s > 0:
                time.sleep(sleep_s)

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


def read_injectors(json_object, inj_duration: int = 2000, verbose: bool = True):
    """
    Read a JSON object and extract injectors specified there.
    :param inj_duration: Duration of the injection in milliseconds
    :param json_object: JSON object or file containing a JSON object
    :param verbose: True if debug information has to be shown
    :return: List of available injectors
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
            job["duration_ms"] = inj_duration
            if job['type'] == 'PortScanningInjector':
                new_inj = PortScanningInjector.fromJSON(job)
            elif job['type'] == 'PacketFloodingInjector':
                new_inj = PacketFloodingInjector.fromJSON(job)
            elif job['type'] == 'IPSpoofingInjector':
                new_inj = IPSpoofingInjector.fromJSON(job)
            elif job['type'] == 'OversizedPacketsInjector':
                new_inj = OversizedPacketsInjector.fromJSON(job)
            elif job['type'] == 'FragmentedPacketsInjector':
                new_inj = FragmentedPacketsInjector.fromJSON(job)
            elif job['type'] == 'MalformedPacketsInjector':
                new_inj = MalformedPacketsInjector.fromJSON(job)
            elif job['type'] == 'ProtocolAnomaliesInjector':
                new_inj = ProtocolAnomaliesInjector.fromJSON(job)
            else:
                new_inj = NetworkLoadInjector.fromJSON(job)
            if new_inj and new_inj.is_valid():
                injectors.append(new_inj)
                if verbose:
                    print(f"New injector loaded from JSON: {new_inj.get_name()}")

    return injectors


if __name__ == "__main__":
    """
    Entry point for the Injector
    """
    # General variables
    out_folder = 'output_folder'
    inj_filename = 'inj_info.csv'
    #inj_json = 'input/injectors_json.json'
    inj_duration_sec = 2
    exp_duration = 20
    randomize = False
    
    
    args = sys.argv
    randomize = False
    inj_json = 'input/injectors_json.json'

    if '-r' in args:
        randomize = True
        try:
            inj_json = args[args.index('-r') + 1]
        except IndexError:
            print("Error: No input file specified after '-r'")
            sys.exit(1)
    else:
        try:
            inj_json = args[1]
        except IndexError:
            print("Error: No input file specified")
            sys.exit(1)
    

    # Extracting definitions of injectors from input JSON
    injectors = read_injectors(inj_json, inj_duration=inj_duration_sec * 1000)

    # Calling injection routine
    inj_timestamps = main_injector(max_n_obs=(inj_duration_sec+1) * injectors.__len__(),
                                   injectors=injectors,
                                   obs_interval_sec=inj_duration_sec,
                                   inj_duration_sec=inj_duration_sec,
                                   inj_cooldown_sec=0,
                                   randomize=randomize,
                                   #inj_probability=0.4,
                                   verbose=True)

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
