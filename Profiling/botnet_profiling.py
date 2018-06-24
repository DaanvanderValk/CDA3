# -*- coding: utf-8 -*-
"""
Created on Fri Jun 22 10:59:47 2018

@author: sande
"""
#Before executing this code, run 
import numpy as np
import pandas as pd
import statistics
def generate_trigrams(data, dimensions):
    occurrences = np.zeros((dimensions,dimensions,dimensions))
    for i in range(0,len(data)-3): 
        a = int(data[i])
        b = int(data[i+1])
        c = int(data[i+2])
        occurrences[a][b][c] = occurrences[a][b][c] + 1
                
        #convert to probabilities
    occurrences_prob = np.true_divide(occurrences, len(data))
    return occurrences_prob

def generate_trigrams_30pct_sample(data, dimensions):
    occurrences = np.zeros((dimensions,dimensions,dimensions))
    selected = 0
    for i in range(0,len(data)-3):
        # Only select 30% of the sequences
        if np.random.rand() > 0.3:
            continue
        
        a = int(data[i])
        b = int(data[i+1])
        c = int(data[i+2])
        occurrences[a][b][c] = occurrences[a][b][c] + 1
        
        selected +=1
                
        #convert to probabilities
    occurrences_prob = np.true_divide(occurrences, selected)
    return occurrences_prob
    
def compute_ngram_difference(ngram1, ngram2,dimensions):
    differences = []
    for i in range (0,dimensions):
        for j in range (0,dimensions):
            for k in range (0,dimensions):
                differences.append(abs(ngram1[i][j][k]-ngram2[i][j][k]))
    return differences

#discretized values of infected host            
df = pd.read_pickle("../Discretization/discretised_dataframe_infected_host")

#number of bins used while discretisation 
dimensions = 15

infected_df = df['code_discretized']

threegrams_infected = generate_trigrams(infected_df, dimensions)

#discretized sequences of infected host 
df = pd.read_pickle("../Discretization/discretised_dataframe_legitimate")
legitimate_df = df['code_discretized']#.sample(n = int(0.4*df.shape[0]))
# Only select 30% of the sequences (see 'Learning Behavioral Fingerprints From Netflows Using Timed Automata', p. 313)
threegrams_legitimate = generate_trigrams_30pct_sample(legitimate_df, dimensions)

#Sum of absolute errors between infected host and legitimate hosts
differences = compute_ngram_difference(threegrams_infected, threegrams_legitimate,dimensions)
print ("Sum of errors from configuration dataset is ",sum(differences))
#Compute thresold value as per p312 of the paper
mean = statistics.mean(differences)
std = statistics.stdev(differences)
#threshold = abs(mean - 2 * std)
threshold = abs(8 * std - mean)
print ("Threshold calcualted is ",threshold)
#All hosts, both infected and normal from https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/
testHosts = ["147.32.84.191", "147.32.84.192", "147.32.84.193", "147.32.84.204", "147.32.84.205", "147.32.84.206",
                 "147.32.84.207", "147.32.84.208", "147.32.84.209", "147.32.84.170", "147.32.84.134", "147.32.84.164"]

#For each host, check the absolute error whether it lies below the threshold
#see 'Learning Behavioral Fingerprints From Netflows Using Timed Automata', p. 312
for testhost in testHosts:
    df_test1 = pd.read_pickle("../Discretization/discretised_dataframe_test"+testhost)
    df_test1 = df_test1['code_discretized']
    threegrams_test1 = generate_trigrams(df_test1, dimensions)

    differences = compute_ngram_difference(threegrams_infected, threegrams_test1,dimensions)
    print ("For host",testhost,"Sum of errors is ", sum(differences))

    if (sum(differences) < threshold):
        print ("infected")
    else:
        print ("Not infected")