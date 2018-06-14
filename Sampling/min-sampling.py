# -*- coding: utf-8 -*-
"""
Created on Thu Jun 14 10:55:31 2018

@author: Daan
"""


if __name__ == "__main__":
    src = '../Data/capture20110816.pcap.netflow.labeled'
    ah = open(src, 'r')
    
    ip_dict = {}
    protocol_set = set()
    flags_set = set()
    tos_set = set()
    label_set = set()
    text_label_set = set()
    
    ah.readline()#skip first line
    counter = 0
    for line_ah in ah:
        line_array = line_ah.strip().split()
        #0: Starting date of the flow (2011-08-16)
        #1: Starting time of the flow (10:01:46.972)
        #2: Duration (4.933)
        #3: Protocol (TCP/UDP)
        #4: Src IP + port
        #5: -
        #6: Dest IP + port
        #7: Flags
        #8: Tos???
        #9: Number of packets in the flow
        #10: Number of bytes transferred in the flow
        #11: Label: always 1?
        #12: Text label (Background / LEGITIMATE / Botnet)
        
            
        protocol_set.add(line_array[3])
        flags_set.add(line_array[7])
        tos_set.add(line_array[8])
        label_set.add(line_array[11])
        text_label_set.add(line_array[12])
        
        # If you want to limit how many lines you read, uncomment this:
#        counter += 1
#        if counter == 5:
#            break
    
    
    print("Distinct protocols:", protocol_set)
    print("Distinct flags:", flags_set)
    print("Distinct tos:", tos_set)
    print("Distinct label_set:", label_set)
    print("Distinct text_label_set:", text_label_set)