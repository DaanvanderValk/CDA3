# -*- coding: utf-8 -*-
"""
Created on Thu Jun 14 11:21:25 2018

@author: sande
"""
import numpy as np
import hashlib


def countIP(ip_dict, ip_addr):
    if ip_addr in ip_dict:
        ip_dict[ip_addr] += 1
    else:
        ip_dict[ip_addr] = 1


if __name__ == "__main__":
    
    height = 4
    width = 10
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
        #print (line_array)
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
        #countIP(ip_dict, ip)
        ip_set.add(ip)
        hash1 = hashlib.md5()
        hash2 = hashlib.sha1()
        for i in range(1,height):
            #m.update(str)
            #hash1.update(line_array[1].encode('utf-8'))
            hash1.update(ip.encode('utf-8'))
            hash2.update(ip.encode('utf-8'))
            #hash2.update(line_array[1].encode('utf-8'))
            hash_n = float.fromhex(hash1.hexdigest()) + (float(i) * float.fromhex(hash2.hexdigest())) 
        #print (int(float(m.hexdigest())))
        #hex_str = "0xAD4"
        #print (type(hex_str))
        #print (type(hash2.hexdigest()))
        #print (float.fromhex(hash2.hexdigest()))
            hex_int = int(hash_n) % width
            #print (hex_int)
            sketch_matrix[i][hex_int] += 1
        #if (counter == 10):
            #print (sketch_matrix)
            #break

    print (sketch_matrix)
    print (sketch_matrix.shape)
    ip_dict = {}
    for ip in ip_set:
        min_count = 999999999999999999999999
        hash3 = hashlib.md5()
        hash4 = hashlib.sha1()
        for i in range(1,height):
            hash3.update(ip.encode('utf-8'))
            hash4.update(ip.encode('utf-8'))
            #hash2.update(line_array[1].encode('utf-8'))
            hash_n = float.fromhex(hash3.hexdigest()) + (float(i) * float.fromhex(hash4.hexdigest())) 
            hex_int = int(hash_n) % width
            if ((sketch_matrix[i][hex_int] < min_count)):
                min_count = sketch_matrix[i][hex_int]
        ip_dict[ip] = min_count
        
    #print (ip_dict)
#        
    ip_frequencies_real = sorted([tuple(reversed(x)) for x in ip_dict.items()])[::-1]

    for i in range(30):
        print("{}: {} occurances".format(ip_frequencies_real[i][1], ip_frequencies_real[i][0]))