# -*- coding: utf-8 -*-
"""
Created on Thu Jun 14 10:55:31 2018

@author: Daan
"""
from queue import PriorityQueue
import numpy as np

# Input: two lists of tuples (which should be ordered beforehand)
def compute_top_10_error(real, estimation):
    error = 0
    for i in range(10):
        current_ip = estimation[i][1]
        if real[i][1] == current_ip:
            continue
        
        for j in range(len(real)):
            if real[j][1] == current_ip:
                #print(i, "Found IP address {} {} places away: adding {} to error.".format(current_ip, np.abs(j - i), np.minimum(10, np.abs(j - i)) * (10 - i)))
                error += np.minimum(10, np.abs(j - i)) * (10 - i)
                break
                
    return error

def countIP(ip_dict, ip_addr):
    if ip_addr in ip_dict:
        ip_dict[ip_addr] += 1
    else:
        ip_dict[ip_addr] = 1

if __name__ == "__main__":
    src = '../Data/capture20110816.pcap.netflow.labeled'
    # We only considered the infected host, as indicated here: (5877 flows)
    # https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/
    infected_host_addr = '147.32.84.165'
    no_reservoirs_tested = 100
    reservoir_sizes = [25, 50, 100, 250, 500, 1000, 2500, 5877]
    
    for reservoir_size in reservoir_sizes:
        
        reservoirs = [PriorityQueue() for _ in range(no_reservoirs_tested)]
        
        # For each reservoir...
        for i in range(no_reservoirs_tested):
            # Fill the first entries with zeros
            for _ in range(reservoir_size):
                reservoirs[i].put((0.0, ""))
        
        ah = open(src, 'r')
        
        ip_dict = {}
        
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
            
            # For each reservoir (remember, we are doing multiple to get a more reliable test)...
            for i in range(no_reservoirs_tested):
                # Create random number and add into the tuple when desired
                random_number = np.random.rand()
                ip_tuple = reservoirs[i].get()
                if ip_tuple[0] < random_number:
                    ip_tuple = (random_number, ip)
            
                reservoirs[i].put(ip_tuple)
            
        
        
        # COUNTING EXACT OCCURANCES
        ip_frequencies_real = sorted([tuple(reversed(x)) for x in ip_dict.items()])[::-1]
        
    #    print("\nReal data: most observed IP addresses with their frequencies:")
    #    for i in range(10):
    #        print("{}: {} occurances".format(ip_frequencies_real[i][1], ip_frequencies_real[i][0]))
    #    
        
        errors = []
        # For each reservoir...
        for i_res in range(no_reservoirs_tested):
            # COUNTING USING THE RESERVOIR
            reservoir_dict = {}
            for i in range(reservoir_size):
                countIP(reservoir_dict, reservoirs[i_res].get()[1])
            ip_frequencies_reservoir = sorted([tuple(reversed(x)) for x in reservoir_dict.items()])[::-1]
            
    #        print("\nReservoir: most observed IP addresses with their frequencies:")
    #        for i in range(10):
    #            print("{}: {} occurances".format(ip_frequencies_reservoir[i][1], ip_frequencies_reservoir[i][0]))
            
            error = compute_top_10_error(ip_frequencies_real, ip_frequencies_reservoir)
    #        print("Reservoir {} has an error of {}".format(i_res, error))
            errors.append(error)
        
        # For the last of the reservoirs, state the top 10 -- as this is required for the report
        print("\nExample reservoir of size {}: most observed IP addresses with their frequencies:".format(reservoir_size))
        for i in range(10):
            print("{}: {} occurances".format(ip_frequencies_reservoir[i][1], ip_frequencies_reservoir[i][0]))
        print("Error for this top 10: {}".format(error))
        
        print("\nAverage error over {} reservoirs of size {}: {}".format(no_reservoirs_tested, reservoir_size, np.average(errors)))