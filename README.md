# Cyber Data Analytics: lab assignment 3
Group 1: Daan van der Valk and Sandesh Manganahalli Jayaprakash

Lab assignment 3 for Cyber Data Analytics, the TU Delft course.

## Installation
All included scripts should be run with Python 3. We used Python 3.6.4 to be specific, but hopefully any Python 3 version would suffice.

The following packages should be installed, which can be done using pip (`pip install <package>`) or Conda (`conda install <package>`), whatever you prefer.

* `matplotlib`
* `scipy`
* `sklearn`
* `pydotplus`
* `graphviz` (depending on the environment, also `python-graphviz`)
* `imblearn`
* `joblib`
* `seaborn`
* `pandas`
* `hashlib`

## Data acquisition
__Note__: the datasets are not included in our repository. Please follow the following steps:

1. Clone this repository.
2. Download the following datasets:
    * For task 1 and 2: the labeled netflows from scenario 6: [capture20110816.pcap.netflow.labeled](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/capture20110816.pcap.netflow.labeled) (245 MB)
    * For task 3 and 4: the labeled netflows from scenario 10: [capture20110818.pcap.netflow.labeled](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/capture20110818.pcap.netflow.labeled) (489 MB)
3. Execute the code - for example, the scripts highlighted below :)

## Highlights
### Min-Wise Sampling
* The technique used and explained: [min-sampling.py](https://github.com/DaanvanderValk/CDA3/blob/master/Sampling/min-sampling.py)
* The included results are generated using [min-sampling-tests.py](https://github.com/DaanvanderValk/CDA3/blob/master/Sampling/min-sampling-tests.py) and produced the output [min-sampling-test-results.md](https://github.com/DaanvanderValk/CDA3/blob/master/Sampling/min-sampling-test-results.md)

### Count-Min Sketching
* The technique explained en iterated over multiple parameters: [count\_min.py](https://github.com/DaanvanderValk/CDA3/blob/master/SketchingTask/count_min.py)
* The results for our best-performing dimensions (relatively): [count\_min\_with\_best\_params.py](https://github.com/DaanvanderValk/CDA3/blob/master/SketchingTask/count_min_with_best_params.py)

### Network Flow Discretization
* Demonstration of technique, including visualizations: [discretization.py](https://github.com/DaanvanderValk/CDA3/blob/master/Discretization/discretization.py)
* The included heatmaps are found in [Heatmap\_legitimate.svg](https://github.com/DaanvanderValk/CDA3/blob/master/Discretization/Heatmap\_legitimate.svg) and [Heatmap\_botnet.svg](https://github.com/DaanvanderValk/CDA3/blob/master/Discretization/Heatmap\_botnet.svg).
* The included plots of the flows:
    * Normal host: [normal\_flow\_encoding\_147.32.84.164.svg](https://github.com/DaanvanderValk/CDA3/blob/master/Discretization/normal_flow_encoding_147.32.84.164.svg) and [normal\_flow\_encoding\_147.32.84.164\_discretized.svg](https://github.com/DaanvanderValk/CDA3/blob/master/Discretization/normal_flow_encoding_147.32.84.164_discretized.svg)
    * Infected host: [botnet\_flow\_encoding\_147.32.84.165.svg](https://github.com/DaanvanderValk/CDA3/blob/master/Discretization/botnet_flow_encoding_147.32.84.165.svg) and [botnet\_flow\_encoding\_147.32.84.165\_discretized.svg](https://github.com/DaanvanderValk/CDA3/blob/master/Discretization/botnet_flow_encoding_147.32.84.165_discretized.svg)
* Discretization as used to profile the infected host and select 30% of the legitimate traffic: [discretization\_for\_ngrams.py](https://github.com/DaanvanderValk/CDA3/blob/master/Discretization/discretization_for_ngrams.py)

### Botnet Profiling
* Profiling of the infected host and applying the detection system: [botnet_profiling.py](https://github.com/DaanvanderValk/CDA3/blob/master/Profiling/botnet_profiling.py)
