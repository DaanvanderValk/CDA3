# -*- coding: utf-8 -*-
"""
Created on Fri Jun 22 10:59:47 2018

@author: sande
"""
import numpy as np
import pandas as pd
import statistics
def generate_trigrams(data, dimensions):
    occurrences = np.zeros((dimensions,dimensions,dimensions))
    sum = 0
    
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
    sum = 0
    
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
                #differences.insert(abs(ngram1[i][j][k]-ngram2[i][j][k]))
                differences.append(abs(ngram1[i][j][k]-ngram2[i][j][k]))

    return differences
                
df = pd.read_pickle("../Discretization/discretised_dataframe_infected_host")

print (df.shape[0])
print (df.head())
#data = pd.DataFrame(data)
#print (data[[0]])
dimensions = 15
#config_data = df.loc[df['label']=='LEGITIMATE']
print (df.code_discretized.unique())
infected_df = df['code_discretized']#.sample(n = int(0.4*df.shape[0]))
print (infected_df.head())
#print (config_data.mean())
#print (config_data.std())
print (type(infected_df))
threegrams_infected = generate_trigrams(infected_df, dimensions)
#print (threegramsprob)

df = pd.read_pickle("../Discretization/discretised_dataframe_legitimate")
legitimate_df = df['code_discretized']#.sample(n = int(0.4*df.shape[0]))
# Only select 30% of the sequences (see 'Learning Behavioral Fingerprints From Netflows Using Timed Automata', p. 313)
threegrams_legitimate = generate_trigrams_30pct_sample(legitimate_df, dimensions)

differences = compute_ngram_difference(threegrams_infected, threegrams_legitimate,dimensions)
#for i in range (0, 100):
#    print (differences[i])
print (sum(differences))
mean = statistics.mean(differences)
std = statistics.stdev(differences)
threshold = abs(mean - 2 * std)
print (threshold)
df_test1 = pd.read_pickle("../Discretization/discretised_dataframe_host1")
df_test1 = df_test1['code_discretized']#.sample(n = int(0.4*df.shape[0]))
threegrams_test1 = generate_trigrams(df_test1, dimensions)

differences = compute_ngram_difference(threegrams_infected, threegrams_test1,dimensions)
#for i in range (0, 100):
#    print (differences[i])

print (sum(differences))
if (sum(differences) < threshold ):
    print ("infected")