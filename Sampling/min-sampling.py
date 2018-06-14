# -*- coding: utf-8 -*-
"""
Created on Thu Jun 14 10:55:31 2018

@author: Daan
"""
from queue import PriorityQueue
import numpy as np

def compute_top_10_error(real, estimation):
    error = 0
    for i in range(10):
        current_ip = estimation[i]
        if real[i] == current_ip:
            continue
        
        for j in range(len(real)):
            if real[j] == current_ip:
                print(i, "Found IP address {} {} places away: adding {} to error.".format(current_ip, np.abs(j - i), np.minimum(10, np.abs(j - i)) * (10 - i)))
                error += np.minimum(10, np.abs(j - i)) * (10 - i)
                break
        
        #print("Found IP address {} nowhere in real data: adding {} to error.".format(current_ip, len(real) * (len(estimation) - i)))
        #error += len(real) * (len(estimation) - i)
                
    return error

def countIP(ip_dict, ip_addr):
    if ip_addr in ip_dict:
        ip_dict[ip_addr] += 1
    else:
        ip_dict[ip_addr] = 1

if __name__ == "__main__":
    src = '../Data/capture20110816.pcap.netflow.labeled'
    # We only considered the infected host, as indicated here:
    # https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/
    infected_host_addr = '147.32.84.165'
    reservoir_size = 5900
    
    reservoir = PriorityQueue()
    for _ in range(reservoir_size):
        reservoir.put((0.0, ""))
    
    ah = open(src, 'r')
    
    ip_dict = {}
    protocol_set = set()
    flags_set = set()
    text_label_set = set()
    
    
    ah.readline()#skip first line
    counter = 0
    for line_ah in ah:
        # Convert the record into an array
        line_array = line_ah.strip().split()
        #0: Starting date of the flow (2011-08-16)
        #1: Starting time of the flow (10:01:46.972)
        #2: Duration (4.933)
        #3: Protocol (TCP/UDP)
        #4: Src IP + port
        #5: -
        #6: Dest IP + port
        #7: Flags
        #8: Tos (always 0)
        #9: Number of packets in the flow
        #10: Number of bytes transferred in the flow
        #11: Label (always 1)
        #12: Text label (Background / LEGITIMATE / Botnet)
        
        source_ip = line_array[4].split(':')[0]
        dest_ip = line_array[6].split(':')[0]
        
        # We are interested in the infected host: which addresses does it connect to?
        # Skip lines that are not from/to this host
        if source_ip != infected_host_addr and dest_ip != infected_host_addr:
            continue
        
        # Let 'ip' store the value of the other host
        if source_ip == infected_host_addr:
            ip = dest_ip
        else:
            ip = source_ip
            
        # Do normal count, to evaluate results
        countIP(ip_dict, ip)
        
        
        # Create random number and add into the tuple when desired
        random_number = np.random.rand()
        ip_tuple = reservoir.get()
        if ip_tuple[0] < random_number:
            ip_tuple = (random_number, ip)
        
        reservoir.put(ip_tuple)
        
        protocol_set.add(line_array[3])
        flags_set.add(line_array[7])
        text_label_set.add(line_array[12])
        
        
        # If you want to limit how many lines you read, uncomment this:
#        counter += 1
#        if counter == 5:
#            break
    
    
    print("Distinct protocols:", protocol_set)
    print("Distinct flags:", flags_set)
    print("Distinct text_label_set:", text_label_set)
    #print("Observed IP addresses with their occurances:", ip_dict)
    
    
    # COUNTING EXACT OCCURANCES
    ip_freqs_real = sorted(ip_dict.values())[::-1] # Frequencies of IPs, ordered from high to low
    ip_sorted_real = sorted(ip_dict, key=ip_dict.__getitem__)[::-1] # IPs, ordered in the frequencies from high to low
    
    print("Real data: 20 most observed IP addresses with their frequencies:")
    for i in range(10):
        print(ip_sorted_real[i], ":", ip_freqs_real[i])
        
        
    # COUNTING USING THE RESERVOIR
    reservoir_dict = {}
    for i in range(reservoir_size):
        countIP(reservoir_dict, reservoir.get()[1])
    
    ip_freqs_reservoir = sorted(reservoir_dict.values())[::-1] # Frequencies of IPs, ordered from high to low
    ip_sorted_reservoir = sorted(reservoir_dict, key=reservoir_dict.__getitem__)[::-1] # IPs, ordered in the frequencies from high to low
    
    print("\nReservoir: 20 most observed IP addresses with their frequencies:")
    for i in range(10):
        print(ip_sorted_reservoir[i], ":", ip_freqs_reservoir[i])
    
    
    print("Error between the two sets:", compute_top_10_error(ip_sorted_real, ip_sorted_reservoir[0:10]))
    print("Error between the two sets:", compute_top_10_error(ip_sorted_real, ip_sorted_reservoir))
    
    
    
    ip_frequencies_real = sorted([tuple(reversed(x)) for x in ip_dict.items()])[::-1]
    ip_frequencies_reservoir = sorted([tuple(reversed(x)) for x in reservoir_dict.items()])[::-1]
    print(ip_thingy)