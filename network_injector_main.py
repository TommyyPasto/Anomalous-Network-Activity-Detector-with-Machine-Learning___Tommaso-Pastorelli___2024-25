import csv
import os
import random
import time
import json
from tqdm import tqdm
from NetworkLoadInjector import LoadInjector, current_ms
from NetworkLoadInjector import NetworkLoadInjector  # Import the new injector

def main_injector(max_n_obs: int, injectors: list, obs_interval_sec: int = 1, inj_duration_sec: int = 1,
                  inj_cooldown_sec: int = 2, inj_probability: float = 0.2, verbose: bool = True):
    """
    Main function for monitoring
    :param inj_cooldown_sec: time to wait after an injection and before activating a new one (seconds)
    :param inj_duration_sec: duration of the injection (seconds)
    :param verbose: True if debug information has to be shown
    :param injectors: list of LoadInjector objects
    :param inj_probability: float number which represents a probability of an injection to take place
    :param obs_interval_sec: seconds in between two observations (seconds)
    :param max_n_obs: maximum number of observations
    :return: list of dictionaries containing activations of injections
    """

    print(f'Injector Started. Active for {max_n_obs} observation cycles.')
    current_inj = None
    inj_timer = 0
    cycle_ms = obs_interval_sec * 1000

    if injectors and len(injectors) > 0:
        for obs_id in tqdm(range(max_n_obs), desc='Injector Progress Bar'):
            start_ms = current_ms()
            if current_inj is None and inj_timer == 0 \
                    and ((max_n_obs - obs_id - 1) * cycle_ms > inj_duration_sec) \
                    and (random.random() <= inj_probability):
                
                # Randomly choose an injector
                while current_inj is None:
                    inj_index = random.randint(0, len(injectors) - 1)
                    if not injectors[inj_index].is_injector_running():
                        current_inj = injectors[inj_index]
                if verbose:
                    #print(f"\n\n\nInjecting with injector '{current_inj.get_name()}'")
                    print(" ")
                    #current_inj.randomize_method_choice()
                    

                # Start the injection thread
                current_inj.inject()
                inj_timer = inj_duration_sec + inj_cooldown_sec

            # Sleep to synchronize with cycle time
            sleep_s = (cycle_ms - (current_ms() - start_ms)) / 1000.0
            if sleep_s > 0:
                time.sleep(sleep_s)

            # Manage cooldown
            inj_timer = inj_timer - cycle_ms if inj_timer > 0 else 0
            if inj_timer < inj_cooldown_sec:
                current_inj = None

    else:
        print("No injectors were set for this experimental campaign")

    activations = []
    for inj in injectors:
        inj_log = inj.get_injections()
        if inj_log:
            new_inj = [dict(item, inj_name=inj.get_name()) for item in inj_log]
            activations.extend(new_inj)
            #if verbose:
                #print(f"Injections with injector '{inj.get_name()}': {len(new_inj)}")

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
            if job['type'] == 'NetworkTraffic':  # Add support for NetworkLoadInjector
                new_inj = NetworkLoadInjector.fromJSON(job)
            else:
                new_inj = LoadInjector.fromJSON(job)
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
    inj_json = 'input/injectors_json.json'
    inj_duration_sec = 2
    exp_duration = 20

    # Extracting definitions of injectors from input JSON
    injectors = read_injectors(inj_json, inj_duration=inj_duration_sec * 1000)

    # Calling injection routine
    inj_timestamps = main_injector(max_n_obs=exp_duration,
                                   injectors=injectors,
                                   obs_interval_sec=1,
                                   inj_duration_sec=inj_duration_sec,
                                   inj_cooldown_sec=2,
                                   inj_probability=0.4,
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
