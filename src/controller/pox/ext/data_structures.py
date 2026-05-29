from typing import *
import networkx as nx
from datetime import datetime
from dataclasses import dataclass, field
from pox.lib.util import dpid_to_str
from pox.openflow.libopenflow_01 import ofp_flow_mod, ofp_action_output


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



@dataclass
class SwitchPort:
    """Represents a physical or virtual port on a switch."""
    port_no: int                        # OpenFlow port number
    hw_addr: str                        # MAC address of the port (e.g. "00:00:00:00:00:01")
    name: str                           # Interface name (e.g. "s1-eth1")
    is_up: bool = True
    neighbor_dpid: Optional[int] = None # DPID of the switch on the other end (if any)
    neighbor_port: Optional[int] = None # Port number on the neighbor switch


@dataclass
class OVSSwitch:
    """
    Represents an OVS switch node in the topology graph.
    Holds all info needed for POX to install flow rules.
    """
    # --- Identity ---
    dpid: int                           # Datapath ID (unique per switch, e.g. 1 for s1)
    name: str                           # Human-readable name (e.g. "s1")

    # --- POX Connection ---
    connection: object = None           # pox.lib.revent / core connection object
                                        # (pox.openflow.Connection, set on switch join)
    is_connected: bool = False

    # --- Port Map ---
    ports: dict[int, SwitchPort] = field(default_factory=dict)
    # key = port_no → SwitchPort

    # --- Flow Table (local mirror) ---
    flow_table: list[dict] = field(default_factory=list)
    # Each entry mirrors what's been installed:
    # {"match": {...}, "actions": [...], "priority": int, "idle_timeout": int}

    # --- Optional metadata ---
    ip: Optional[str] = None            # Management IP if needed
    capabilities: int = 0               # OpenFlow capability flags from features reply

    def send_flow_mod(self, match, actions, priority=1000,
                      idle_timeout=0, hard_timeout=0):
        """
        Install a flow rule on this switch via its POX connection.
        """

        if not self.connection:
            raise RuntimeError(f"Switch {self.name} has no active connection")

        msg = ofp_flow_mod()
        msg.match = match
        msg.priority = priority
        msg.idle_timeout = idle_timeout
        msg.hard_timeout = hard_timeout
        msg.actions = actions
        self.connection.send(msg)

        # Mirror locally
        self.flow_table.append({
            "match": match, "actions": actions,
            "priority": priority
        })

    def get_port_toward(self, neighbor_dpid: int) -> Optional[SwitchPort]:
        """Return the local port that faces a given neighbor switch."""
        return next(
            (p for p in self.ports.values() if p.neighbor_dpid == neighbor_dpid),
            None
        )

    def __hash__(self):
        return hash(self.dpid)          # Required for use as a NetworkX node key

    def __eq__(self, other):
        return isinstance(other, OVSSwitch) and self.dpid == other.dpid

    def __repr__(self):
        return f"OVSSwitch(name={self.name}, dpid={self.dpid}, connected={self.is_connected})"

@dataclass
class Link:
    """
    Represents a directed or undirected link between two OVS switches.
    Stored as edge attributes in the NetworkX graph.
    """
    src_dpid: int
    dst_dpid: int
    src_port: int       # Port number on the source switch
    dst_port: int       # Port number on the destination switch
    nominal_bandwidth: float = 100.0   # Mbps — useful for weighted routing
    residual_bandwidth: float = 100.0          # ms
    delay: float = 1.0
    is_up: bool = True

    def reverse(self) -> "Link":
        """Return the link in the opposite direction."""
        return Link(self.dst_dpid, self.src_dpid,
                    self.dst_port, self.src_port,
                    self.nominal_bandwidth, self.residual_bandwidth,self.delay, self.is_up)

class Topology:
    def __init__(self):
        self.graph = nx.Graph()          # or DiGraph if you need directed flows

    def add_switch(self, switch: OVSSwitch):
        # Node key = dpid (int), node object stored as attribute
        self.graph.add_node(switch.dpid, switch=switch)

    def add_link(self, link: Link):
        self.graph.add_edge(
            link.src_dpid, link.dst_dpid,
            link=link,
            weight=link.delay           # use delay (or 1/bandwidth) for shortest path
        )
        # Also cross-populate the port neighbor info on each switch
        src_sw = self.get_switch(link.src_dpid)
        # dst_sw = self.get_switch(link.dst_dpid)
        if src_sw and link.src_port in src_sw.ports:
            src_sw.ports[link.src_port].neighbor_dpid = link.dst_dpid
            src_sw.ports[link.src_port].neighbor_port = link.dst_port

    def get_switch(self, dpid: int) -> Optional[OVSSwitch]:
        node = self.graph.nodes.get(dpid)
        return node["switch"] if node else None

    def install_path(self, path: list[int], match_template):
        """
        Given an ordered list of DPIDs, install forwarding rules hop by hop.
        path = [dpid_A, dpid_B, dpid_C]
        """
        for i, dpid in enumerate(path[:-1]):
            next_dpid = path[i + 1]
            sw = self.get_switch(dpid)
            port = sw.get_port_toward(next_dpid)
            if port:
                sw.send_flow_mod(
                    match=match_template,
                    actions=[ofp_action_output(port=port.port_no)]
                )

@dataclass
class Worker:
    ip: str
    flow_id: int
    connected_to_dpid: Optional[int] = None
    connected_port: Optional[int] = None

@dataclass
class Collector:
    ip: str
    flow_id: int
    connected_to_dpid: Optional[int] = None
    connected_port: Optional[int] = None
    
@dataclass
class Flow:
    ID: str 
    workers: List[Worker] = field(default_factory=list)
    collector: Optional[Collector] = None
    D: int = 0
    completion_time: int = 0
    phase: float = 0.0
    sTime: Optional[datetime] = None 
    ftime: Optional[datetime] = None

@dataclass
class TrainingProcedure:
    flows: List[Flow] = field(default_factory=list)
    D: int = 0
    completion_time: int = 0
    phase: float = 0.0
    K: int = 0
  
training_procedures : List[TrainingProcedure] = []
  


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