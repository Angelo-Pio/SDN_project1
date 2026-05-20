
import networkx as nx

# For each training procedure v you need to mantain:
# ! Global structures:
# Graph(N,L) , node , link 
# Node: ID, type : collector, worker, switch , {link : ip} 
# Link: src_node, dst_node, residual_capacity , src_ip, dst_ip
# Capacity = 100 #Mbps
# * Set of workers: W -> division of workers by "color" subsets
# * Worker: IP, flow_id, 
# * Collector: IP, flow_id
# * Flow: workers, collector, ID , Dv , Tv = null, phase = null, stime = first time at which traffic from a worker
# * that belongs to the flow has been detected, ftime = last time ... 
# * Training_Procedure [ (Flows, D, T , phase, K), (Flows) ]  

#! Global Variables

# Graph
# Current_procedure_id
# TrainingProcedures = []
# Capacity



# TODO:
# 1. Finalizing graph, node and link data structures
# 2. Populating statically the grah with netw topology and collectors
# 3. Undestrand how to discover workers and populate Flow.workers for a Flow 
# 4. Undestainding how to update link residual_capacity(how much data coming from a worker etc.)