from src.controller.pox.ext.data_structures import Collector, Link, OVSSwitch, Topology
from data_structures import *
from pox.core import core
from pox.openflow.libopenflow_01 import *
import pox.lib.packet as pkt
import networkx as nx
from datetime import datetime

class LoadBalancer:

    def __init__(self):
        core.openflow.addListeners(self)
        self.topology = None


    def populate_static_topology(self):
        # 2 Spines, 5 Leaves
        # Ensure DPIDs are integers matching what OVS passes to POX
        spines = [
            OVSSwitch(dpid=101, name="s1"), 
            OVSSwitch(dpid=102, name="s2")
        ]
        leaves = [
            OVSSwitch(dpid=1, name="l1"),
            OVSSwitch(dpid=2, name="l2"),
            OVSSwitch(dpid=3, name="l3"),
            OVSSwitch(dpid=4, name="l4"),
            OVSSwitch(dpid=5, name="l5")
        ]

        topo = Topology()
        
        for sw in spines + leaves:
            topo.add_switch(sw)
        
        # Fix
        topo.add_link(Link(src_dpid=1, dst_dpid=101, src_port=1, dst_port=1))
        topo.add_link(Link(src_dpid=1, dst_dpid=102, src_port=1, dst_port=1))
        topo.add_link(Link(src_dpid=2, dst_dpid=101, src_port=1, dst_port=1))
        topo.add_link(Link(src_dpid=2, dst_dpid=102, src_port=1, dst_port=1))
        topo.add_link(Link(src_dpid=3, dst_dpid=101, src_port=1, dst_port=1))
        topo.add_link(Link(src_dpid=3, dst_dpid=102, src_port=1, dst_port=1))
        topo.add_link(Link(src_dpid=4, dst_dpid=101, src_port=1, dst_port=1))
        topo.add_link(Link(src_dpid=4, dst_dpid=102, src_port=1, dst_port=1))
        topo.add_link(Link(src_dpid=5, dst_dpid=101, src_port=1, dst_port=1))
        topo.add_link(Link(src_dpid=5, dst_dpid=102, src_port=1, dst_port=1))

        self.topology = topo

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        # Check if it's an IP packet (Worker sending data)
        ip_packet = packet.find('ipv4')
        if ip_packet is not None:
            src_ip = str(ip_packet.srcip)
            in_port = event.port
            sw_dpid = event.dpid

            # TODO: find worker's flow id and register worker in training procedure
            # TODO: understand how to handle training procedures (e.g., recognize when a new one starts or the current one ends)
            
            self.register_or_update_worker(self, src_ip, sw_dpid, in_port)

            # TODO: find data rate and/or install flow rules

    def register_or_update_worker(self, ip: str, dpid: int, port: int):
        # Check if worker already exists in our active Flow
        if self.active_flow:
            for w in self.active_flow.workers:
                if w.ip == ip:
                    return
                    
            # New worker detected!
            new_worker = Worker(ip=ip, flow_id=self.active_flow.ID, connected_to_dpid=dpid, connected_port=port)
            self.active_flow.workers.append(new_worker)
            
            if self.active_flow.sTime is None:
                self.active_flow.sTime = datetime.now()

    def route_worker_to_collector(self, worker: Worker, collector: Collector, topo: Topology, estimated_rate: float):
        
        graph = topo.graph
    
        # Define a custom weight function for NetworkX that filters out saturated links
        def cspf_weight(u, v, edge_attr):
            link_obj = edge_attr["link"]
            is_final_hop = (v == collector.connected_to_dpid)

            if not link_obj.is_up:
                return float('inf') # Block this edge completely

            if not is_final_hop and link_obj.residual_bandwidth < estimated_rate:
                return float('inf') # Block this edge completely
            
            # Prefer paths with more breathing room (lower utilization)
            utilization = (link_obj.nominal_bandwidth - link_obj.residual_bandwidth) / link_obj.nominal_bandwidth
            return 1.0 + utilization 

        try:
            # Calculate optimal path from the worker's leaf switch to collector's leaf switch
            path = nx.shortest_path(
                graph, 
                source=worker.connected_to_dpid, 
                target=collector.connected_to_dpid, 
                weight=cspf_weight
            )
            
            # Deduct used bandwidth along the selected path
            for i in range(len(path) - 1):
                u, v = path[i], path[i+1]
                graph[u][v]["link"].residual_bandwidth -= estimated_rate
                
            # Install the rules step-by-step to open flow paths
            topo.install_path(path, match_template=ofp_match(dl_type=0x0800, nw_src=worker.ip))
            
            # Don't forget the final hop out of the destination switch to the collector itself!
            dest_sw = topo.get_switch(collector.connected_to_dpid)
            dest_sw.send_flow_mod(
                match=ofp_match(dl_type=0x0800, nw_src=worker.ip),
                actions=[ofp_action_output(port=collector.connected_port)]
            )
            
        except nx.NetworkXNoPath:
            print(f"Warning: Traffic bottleneck hit! No available inner fabric paths for worker {worker.ip}")


    def check_flow(self):
        # TODO: check all flows and set ftime when a flow is not used for some time (routine)
        # TODO: check if no data has been sent in this time or update flow.D if data was sent
        flow.ftime = datetime.now()

    def check_residual_capacity(self):
        # TODO: update link residual capacity in graph

    def estimate_flow_data(self):
        # TODO: estimate the quantities requested in the text for a flow

    def estimate_tp_data(self):
        # TODO: estimate the quantities requested in the text for a training procedure