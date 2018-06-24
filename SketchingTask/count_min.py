# -*- coding: utf-8 -*-
"""
Created on Thu Jun 14 11:21:25 2018

@author: sande
"""
#This code is to evaluate best height and width of count-min sketch matrix
import numpy as np
import hashlib


def countIP(ip_dict, ip_addr):
    if ip_addr in ip_dict:
        ip_dict[ip_addr] += 1
    else:
        ip_dict[ip_addr] = 1

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

if __name__ == "__main__":
    
    h = [5,10,15,20,25,30,35,40]
    w = [20,25,30,35,40,45,50,55,60]
    for height in h:
        for width in w:
            ip_dict = {}
            infected_host_addr = '147.32.84.165'
            sketch_matrix = np.ones((height,width))
            src = '../Data/capture20110816.pcap.netflow.labeled'
            ah = open(src, 'r')
        
            ah.readline()#skip first line
            counter = 0
            ip_set = set()
            
            for line_ah in ah:
                counter += 1
                line_array = line_ah.strip().split()
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
                    
                #Do normal count, to evaluate results
                countIP(ip_dict, ip)
                ip_set.add(ip)
                #use md5 and SHA-1 hashing algorithms and build new hash values as per
                #this paper https://www.eecs.harvard.edu/~michaelm/postscripts/tr-02-05.pdf
                hash1 = hashlib.md5()
                hash2 = hashlib.sha1()
                for i in range(1,height):
                    hash1.update(ip.encode('utf-8'))
                    hash2.update(ip.encode('utf-8'))
                    
                    hash_n = float.fromhex(hash1.hexdigest()) + (float(i) * float.fromhex(hash2.hexdigest())) 
                    # take modulus of the hashed value so that the entry corresponding to that column can be incremented
                    hex_int = int(hash_n) % width
                    sketch_matrix[i][hex_int] += 1
            # COUNTING EXACT OCCURANCES
            ip_frequencies_real = sorted([tuple(reversed(x)) for x in ip_dict.items()])[::-1]
            ip_dict_hash = {}
            for ip in ip_set:
                min_count = 999999999999999999999999
                hash3 = hashlib.md5()
                hash4 = hashlib.sha1()
                for i in range(1,height):
                    hash3.update(ip.encode('utf-8'))
                    hash4.update(ip.encode('utf-8'))
                    hash_n = float.fromhex(hash3.hexdigest()) + (float(i) * float.fromhex(hash4.hexdigest())) 
                    hex_int = int(hash_n) % width
                    if ((sketch_matrix[i][hex_int] < min_count)):
                        min_count = sketch_matrix[i][hex_int]
                ip_dict_hash[ip] = min_count

            ip_frequencies_hash = sorted([tuple(reversed(x)) for x in ip_dict_hash.items()])[::-1]
            
            print ("For height {} and width {}".format(height,width))
            print("Error of the top 10 (minimal: 0, maximal: 550):", compute_top_10_error(ip_frequencies_real, ip_frequencies_hash))    
            