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
    
    infected_host_addr = '147.32.84.164'
    
    
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
    
    
    discrete_protocols = ['TCP', 'UDP', 'ICMP']
    discrete_flags = ["FRPA_", "INT", "A_", "FPA_", "PA_", "URP", "_FSPA", "S_", "SPA_", "RA_", "FA_", "SRPA_", "R_",
     "FSPA_", "RED", "SA_", "URN", "ECO", "_FSA", "FSRPA_", "URFIL", "URH", "FRA_", "CON", "FSA_",
     "RPA_", "_FSRPA", "ECR", "FS_", "TXD", "SEC_", "SR_", "FSRA_", "F_", "URHPRO", "NNS", "SRA_", "SRC",
     "_FSRA", "AC_", "NRA", "SPAC_", "PAC_", "FSAU_", "FSRPAC_", "URO", "FRPAC_", "RC_", "URNPRO",
     "FSPAC_", "URF", "FPAC_", "FSR_", "_FSPAC", "FSPAEC_", "FAU_", "MAS", "TST", "IRR", "RTS", "RTA",
     "IRQ", "UNK", "MSR", "TSR", "SEC", "ROB", "MRQ", "IAH", "DNQ", "PTB", "PAR", "WAY", "PHO", "___", "AHA",
     "NRS", "MHR", "UR", "NNA", "MRP", "TRC", "DCE", "SKP", "DNP", "URPRE", "URS", "URNU", "URCUT",
     "URISO", "URHTOS", "URHU", "FRAC_", "SRC_", "RPA_FRPA"]
    
    
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
        
        
        # Skip lines that are background traffic
        if line_array[12] == 'Background':
            continue
        
        source = line_array[4].split(':')
        dest = line_array[6].split(':')
        
        # Append to lists, to be combined into dataframe
        list_protocols.append(line_array[3])
        list_flags.append(line_array[7])
        list_text_labels.append(line_array[12])
        
        counter +=1
        
        if counter > 5:
            break
        
    
    print("Done reading data.")
    
    
    # Create dataframe of the collected data
    df = pd.DataFrame({'protocol': list_protocols,
     'flags': list_flags,
     'label': list_text_labels
    })
    
    
    
    
    
    
    # VISUALIZATION
    
    # Dimensions of the heatmaps; useful for tweaking.
    x_size = 14
    y_size = 2
    
    # Select the features to be plotted here
    # The features should be categorical, as their unique values are used
    feature1 = 'protocol'
    feature2 = 'flags'
    
    # Save the heatmaps to SVG files?
    saveToFiles = False
    
    # If the heatmaps should be saved, use current datetime to avoid overwriting existing files
    preFileName = datetime.datetime.now().strftime("%d-%m-%y %H.%M.%S")
    
    
    # Only select items we need
    df = df[['label', feature1, feature2]]
    
    # Drop empty values
    df = df.dropna()
    
    # Show which distinct values the selected features can take
    feature1_values = df[feature1].unique()
    feature2_values = df[feature2].unique()
    
    print(feature1, "values:", feature1_values)
    print(feature2, "values:", feature2_values)
    
    # Only take the verified botnet and non-botnet cases
    # Note that "Refused" records are ignored, as we don't know wether it's due to botnet or something else.
    df_legitimate = df[df['label'] == 'LEGITIMATE']
    print('"legitimate" records:', len(df_legitimate))
    df_botnet = df[df['label'] == 'Botnet']
    print('"botnet" records:', len(df_botnet))
    
    # To make the heatmap, we need to group the occurances of combinations of both features
    legitimate_grouped = df_legitimate.groupby([feature1, feature2]).size()
    legitimate_occurence = legitimate_grouped.reset_index()
    legitimate_occurence.columns = [feature1, feature2, '']

    botnet_grouped = df_botnet.groupby([feature1, feature2]).size()
    botnet_occurence = botnet_grouped.reset_index()
    botnet_occurence.columns = [feature1, feature2, '']

    # Finally, a pivot of this data will be the input of our heatmap
    # This is a 2-dimensional dataframe (feature1 X feature2)
    # The values in the dataframe indicate the number of occurances of the x and y values
    # Also relative matrixes are computed (containing percentages)
    legitimate_pivot = legitimate_occurence.pivot(feature1, feature2).fillna(0)
    botnet_pivot = botnet_occurence.pivot(feature1, feature2).fillna(0)
    
    # We want ALL possible feature values included in the heatmap,
    # including the values that do not occur in a certain part of the dataset.
    for feature1_value in feature1_values:
        if feature1_value not in legitimate_pivot.index.values:
            # Force empty row into dataframe
            legitimate_pivot.loc[feature1_value] = 0.0
        if feature1_value not in botnet_pivot.index.values:
            # Force empty row into dataframe
            botnet_pivot.loc[feature1_value] = 0.0
    
    for feature2_value in feature2_values:
        if ('', feature2_value) not in legitimate_pivot.columns:
            # Force empty column into dataframe
            legitimate_pivot['', feature2_value] = 0.0
        if ('', feature2_value) not in botnet_pivot.columns:
            # Force empty column into dataframe
            botnet_pivot['', feature2_value] = 0.0
            
    # Reorder indexes of the dataframes in both dimensions
    legitimate_pivot = legitimate_pivot.sort_index().sort_index(axis=1)
    botnet_pivot = botnet_pivot.sort_index().sort_index(axis=1)
    all_pivot = legitimate_pivot + botnet_pivot
    
    # Compute fraction of botnet compared to legitimate ones
    fraction_botnet = botnet_pivot / all_pivot
    
    # Because the distribution of such occurances is far from linear, we usually want to look
    # at the graph on a logarithmic scale. This is achieved by replacing each value in the
    # dataframe to log(1 + value). This maps the interval [0, <very high values>] to
    # [0, <relatively low value>], which is exactly what we want.
    legitimate_pivot_log = np.log(1 + legitimate_pivot)
    botnet_pivot_log = np.log(1 + botnet_pivot)

    # legitimate - logarithmic scale
    plt.subplots(figsize=(x_size, y_size))
    ax_normal = plt.axes()
    sns.heatmap(legitimate_pivot_log, ax = ax_normal, cmap="GnBu")
    #ax_normal.set_title('legitimate records (logarithmic scale)')
    ax_normal.set_xlabel(feature2)
    ax_normal.set_ylabel(feature1)
    if saveToFiles:
        plt.savefig(preFileName + " - legitimate.svg", bbox_inches='tight')

    # botnetulent - logarithmic scale
    plt.subplots(figsize=(x_size, y_size))
    ax_normal = plt.axes()
    sns.heatmap(botnet_pivot_log, ax = ax_normal, cmap="GnBu")
    #ax_normal.set_title('botnetulent records (logarithmic scale)')
    ax_normal.set_xlabel(feature2)
    ax_normal.set_ylabel(feature1)
    if saveToFiles:
        plt.savefig(preFileName + " - botnet.svg", bbox_inches='tight')
    
    # Differences - linear scale
    plt.subplots(figsize=(x_size, y_size))
    ax_normal = plt.axes()
    sns.heatmap(fraction_botnet, ax = ax_normal, center=0, cmap="PiYG_r")
    #ax_normal.set_title('Fraction of botnetulent transactions')
    ax_normal.set_xlabel(feature2)
    ax_normal.set_ylabel(feature1)
    
    if saveToFiles:
        plt.savefig(preFileName + " - fraction.svg", bbox_inches='tight')
    
    