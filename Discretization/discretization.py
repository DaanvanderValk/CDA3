# -*- coding: utf-8 -*-
"""
Created on Thu Jun 14 10:55:31 2018

@author: Daan
"""
import time
import numpy as np
import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt
import datetime

def increase_dict_counter(dictionary, key):
    if key in dictionary:
        dictionary[key] += 1
    else:
        dictionary[key] = 1


if __name__ == "__main__":
    src = '../Data/capture20110818.pcap.netflow.labeled'
#    There are several infected hosts in this system:
#    - 147.32.84.165
#    - 147.32.84.191
#    - 147.32.84.192
#    - 147.32.84.193
#    - 147.32.84.204
#    - 147.32.84.205
#    - 147.32.84.206
#    - 147.32.84.207
#    - 147.32.84.208
#    - 147.32.84.209
#    And there are a couple of normal hosts (background traffic) in this system:
#    - 147.32.84.170
#    - 147.32.84.134
#    - 147.32.84.164
#    (servers are excluded, see:)
#    https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/
    
    ah = open(src, 'r')
    
    list_protocols = []
    list_flags = []
    list_text_labels = []
    
    # Possible flags:
    # FRPA_, INT, A_, FPA_, PA_, URP, _FSPA, S_, SPA_, RA_, FA_, SRPA_, R_,
    # FSPA_, RED, SA_, URN, ECO, _FSA, FSRPA_, URFIL, URH, FRA_, CON, FSA_,
    # RPA_, _FSRPA, ECR, FS_, TXD, SEC_, SR_, FSRA_, F_, URHPRO, NNS, SRA_, SRC,
    # _FSRA, AC_, NRA, SPAC_, PAC_, FSAU_, FSRPAC_, URO, FRPAC_, RC_, URNPRO,
    # FSPAC_, URF, FPAC_, FSR_, _FSPAC, FSPAEC_, FAU_, MAS, TST, IRR, RTS, RTA,
    # IRQ, UNK, MSR, TSR, SEC, ROB, MRQ, IAH, DNQ, PTB, PAR, WAY, PHO, ___, AHA,
    # NRS, MHR, UR, NNA, MRP, TRC, DCE, SKP, DNP, URPRE, URS, URNU, URCUT,
    # URISO, URHTOS, URHU, FRAC_, SRC_, RPA_FRPA
    
    # Possible protocols:
    # TCP, UDP, ICMP, PIM, RTP, ARP, IPX/SPX, RTCP, IGMP, IPV6-ICMP, IPV6, ESP, LLC, UDT
    # However, only TCP, UDP and ICMP are found in the non-background traffic: only they are collected
    
    discrete_protocols = ['TCP', 'UDP', 'ICMP']
    discrete_flags = ["FRPA_", "INT", "A_", "FPA_", "PA_", "URP", "_FSPA", "S_", "SPA_", "RA_", "FA_", "SRPA_", "R_",
     "FSPA_", "RED", "SA_", "URN", "ECO", "_FSA", "FSRPA_", "URFIL", "URH", "FRA_", "CON", "FSA_",
     "RPA_", "_FSRPA", "ECR", "FS_", "TXD", "SEC_", "SR_", "FSRA_", "F_", "URHPRO", "NNS", "SRA_", "SRC",
     "_FSRA", "AC_", "NRA", "SPAC_", "PAC_", "FSAU_", "FSRPAC_", "URO", "FRPAC_", "RC_", "URNPRO",
     "FSPAC_", "URF", "FPAC_", "FSR_", "_FSPAC", "FSPAEC_", "FAU_", "MAS", "TST", "IRR", "RTS", "RTA",
     "IRQ", "UNK", "MSR", "TSR", "SEC", "ROB", "MRQ", "IAH", "DNQ", "PTB", "PAR", "WAY", "PHO", "___", "AHA",
     "NRS", "MHR", "UR", "NNA", "MRP", "TRC", "DCE", "SKP", "DNP", "URPRE", "URS", "URNU", "URCUT",
     "URISO", "URHTOS", "URHU", "FRAC_", "SRC_", "RPA_FRPA"]
    
    space = len(discrete_protocols) * len(discrete_flags)
    # Ideally, the number of bins should be a multiple of 3, to nicely separate the 3 protocols
    number_of_bins = 15
    
    # Keep a list of the flow codes in a dict for each of the mentoined hosts
    list_hosts = {
            # Infected hosts
            "147.32.84.165": True,
            "147.32.84.191": True,
            "147.32.84.192": True,
            "147.32.84.193": True,
            "147.32.84.204": True,
            "147.32.84.205": True,
            "147.32.84.206": True,
            "147.32.84.207": True,
            "147.32.84.208": True,
            "147.32.84.209": True,
            # Normal hosts
            "147.32.84.170": False,
            "147.32.84.134": False,
            "147.32.84.164": False
        }
    list_flow_codes = []
    dict_flow_lists = {key: [] for key in list_hosts.keys()}
    dict_flow_lists_bins = {key: [] for key in list_hosts.keys()}
    
    
    code = 0
    # Compute the factor for each first iteration of the encoding algorithm (e.g., i=0)
    # This is equal to spaceSize / |M1|
    #     = (len(discrete_protocols) * len(discrete_flags)) / len(discrete_protocols)
    #     = len(discrete_flags)
    initialSpaceDevM1 = len(discrete_flags)
    
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
#        if line_array[12] == "Background":
#            continue
        
        
        source_ip = line_array[4].split(':')[0]
        dest_ip = line_array[6].split(':')[0]
        
        # We are interested in the infected host: which addresses does it connect to?
        # Skip lines that are not from/to this hosts
        if source_ip in list_hosts.keys():
            host = source_ip
        elif dest_ip in list_hosts.keys():
            host = dest_ip
        else:
            continue
        
        # Append to lists, to be combined into dataframe
        protocol = line_array[3]
        flags = line_array[7]
        
        list_protocols.append(protocol)
        list_flags.append(flags)
        list_text_labels.append(line_array[12])
        
        # Compute the encoding of this flow.
        # This is equivalent to Algorithm 1 (p. 311) in
        # 'Learning Behavioral Fingerprints From Netflows Using Timed Automata'
        code = discrete_protocols.index(protocol) * initialSpaceDevM1 + discrete_flags.index(flags)
        dict_flow_lists[host].append(code)
        
        # Discretize this encoding even further, into the number of bins defined before
        dict_flow_lists_bins[host].append(np.floor(float(code)/space*number_of_bins))
        
        counter +=1
        
        
    
    print("Done reading data: {} records included.".format(counter))
    
    
    # Create dataframe of the collected data
    df = pd.DataFrame({'protocol': list_protocols,
     'flags': list_flags,
     'label': list_text_labels,
     'code': list_flow_codes
    })
    
        
    # VISUALIZATION
    figsize = (7, 2.5)
    saveToFiles = False
    
    # The hosts shown in the report:
    # Infected: 147.32.84.165
    # Normal:   147.32.84.164
    
    for host in list_hosts.keys():
        plt.figure(figsize=figsize)
        #plt.suptitle("Data for host {} which is {}infected".format(host, "" if list_hosts[host] else "not "))
        plt.plot(dict_flow_lists[host], color = "lightcoral" if list_hosts[host] else "lightgreen")
        plt.ylabel("Flow encoding")
        plt.xlabel("Packets for this host")
        
        if saveToFiles:
            plt.savefig(("botnet" if list_hosts[host] else "normal") + "_flow_encoding_"+ host +".svg", bbox_inches='tight')
        
        plt.figure(figsize=figsize)
        #plt.suptitle("Data for host {} which is {}infected (discretized)".format(host, "" if list_hosts[host] else "not "))
        plt.plot(dict_flow_lists_bins[host], color = "red" if list_hosts[host] else "green")
        plt.ylabel("Flow encoding (discretized)")
        plt.xlabel("Packets for this host")
        
        if saveToFiles:
            plt.savefig(("botnet" if list_hosts[host] else "normal") + "_flow_encoding_"+ host +"_discretized.svg", bbox_inches='tight')
