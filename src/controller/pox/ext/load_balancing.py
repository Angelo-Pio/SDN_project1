from data_structures import *
from pox.core import core
from pox.openflow.libopenflow_01 import *
import pox.lib.packet as pkt
import networkx as nx
from datetime import datetime
from pox.lib.recoco import Timer

# Currently trying to fix switches not connecting and installing networkx in controller

log = core.getLogger()

class LoadBalancer:

    def __init__(self):
        core.openflow.addListeners(self)
        self.topology = self.populate_static_topology()
        
        self.flows = {}             # Maps flow_id -> Flow
        self.collectors = {}        # Maps flow_id -> Collector
        self.worker_to_flow = {}    # Maps worker IP -> flow_id
        self.port_stats = {}        # Maps (dpid, port) -> (last_tx_bytes, last_timestamp)
        self.worker_tp_ids = {}     # Maps worker IP -> current tp_id (int)
        
        Timer(5, self.routine_checks, recurring=True)
        
        self.populate_mappings()
        log.info("LoadBalancer initialized. Recurring checks started.")

    def populate_mappings(self):
        collector1 = Collector(ip="10.0.1.1", flow_id=1, connected_to_dpid=3, connected_port=0)
        collector2 = Collector(ip="10.0.1.2", flow_id=2, connected_to_dpid=3, connected_port=1)
        collector3 = Collector(ip="10.0.1.3", flow_id=3, connected_to_dpid=3, connected_port=2)
        collector4 = Collector(ip="10.0.1.4", flow_id=4, connected_to_dpid=3, connected_port=3)
        self.collectors = {
            1: collector1,
            2: collector2,
            3: collector3,
            4: collector4
        }

        flow1 = Flow(ID=1, collector=collector1)
        flow2 = Flow(ID=2, collector=collector2)
        flow3 = Flow(ID=3, collector=collector3)
        flow4 = Flow(ID=4, collector=collector4)
        self.flows = {
            1: flow1,
            2: flow2,
            3: flow3,
            4: flow4
        }



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
        topo.add_link(Link(src_dpid=1, dst_dpid=101, src_port=0, dst_port=0))
        topo.add_link(Link(src_dpid=1, dst_dpid=102, src_port=1, dst_port=0))
        topo.add_link(Link(src_dpid=2, dst_dpid=101, src_port=0, dst_port=1))
        topo.add_link(Link(src_dpid=2, dst_dpid=102, src_port=1, dst_port=1))
        topo.add_link(Link(src_dpid=3, dst_dpid=101, src_port=0, dst_port=2))
        topo.add_link(Link(src_dpid=3, dst_dpid=102, src_port=1, dst_port=2))
        topo.add_link(Link(src_dpid=4, dst_dpid=101, src_port=0, dst_port=3))
        topo.add_link(Link(src_dpid=4, dst_dpid=102, src_port=1, dst_port=3))
        topo.add_link(Link(src_dpid=5, dst_dpid=101, src_port=0, dst_port=4))
        topo.add_link(Link(src_dpid=5, dst_dpid=102, src_port=1, dst_port=4))

        return topo

    def _handle_ConnectionUp(self, event):
        # Link the POX connection to our topology model
        sw = self.topology.get_switch(event.dpid)
        if sw:
            sw.connection = event.connection
            sw.is_connected = True
            
        # Proactively flood ARP packets so workers can resolve MAC addresses
        msg = ofp_flow_mod()
        msg.match = ofp_match(dl_type=0x0806)
        msg.actions.append(ofp_action_output(port=OFPP_FLOOD))
        event.connection.send(msg)
        log.info(f"Installed ARP flood rule on switch {event.dpid}")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        # Check if it's an IP packet (Worker sending data)
        ip_packet = packet.find('ipv4')
        if ip_packet is not None:
            src_ip = str(ip_packet.srcip)
            dst_ip = str(ip_packet.dstip)
            in_port = event.port
            sw_dpid = event.dpid

            # TODO: find worker's flow id and register worker in training procedure
            flow_id = self.worker_to_flow.get(src_ip)
            if flow_id is None:
                for id, collector in self.collectors.items():
                    if collector.ip == dst_ip:
                        flow_id = id
                        break
            if flow_id is None:
                return # Packet from an unknown worker
            
            self.worker_to_flow[src_ip] = flow_id
            
            # --- Handle Overlapping Training Procedures ---
            tp_id = self.worker_tp_ids.setdefault(src_ip, 0)
            
            # Ensure the TrainingProcedure for this iteration exists
            while len(training_procedures) <= tp_id:
                training_procedures.append(TrainingProcedure(id=len(training_procedures)))
                
            tp = training_procedures[tp_id]
            
            # Find or create the Flow inside this specific TP
            flow = next((f for f in tp.flows if f.ID == flow_id), None)
            if flow is None:
                collector = self.collectors.get(flow_id)
                flow = Flow(ID=flow_id, collector=collector)
                tp.flows.append(flow)
                
            worker = self.register_or_update_worker(src_ip, sw_dpid, in_port, flow)
            if not worker:
                return
            
            # Learn K (total number of discovered workers)
            tp.K = len(self.worker_to_flow)
            
            collector = self.collectors.get(flow_id)
            if not collector:
                return # Collector not defined for this flow
                
            # Calculate expected throughput C / K (where C is the 100 Mbps link capacity)
            estimated_rate = 100.0 / tp.K
            
            log.info(f"New burst from {src_ip} (Flow {flow_id}, TP {tp_id}). K={tp.K}, Est Rate={estimated_rate:.2f} Mbps")
            
            self.route_worker_to_collector(worker, collector, self.topology, estimated_rate)

            # TODO: find data rate and/or install flow rules

    def register_or_update_worker(self, ip: str, dpid: int, port: int, flow: Flow):
        for w in flow.workers:
            if w.ip == ip:
                return w
                
        # New worker detected!
        new_worker = Worker(ip=ip, flow_id=flow.ID, connected_to_dpid=dpid, connected_port=port)
        flow.workers.append(new_worker)
        
        if flow.sTime is None:
            flow.sTime = datetime.now()
            
        return new_worker

    def route_worker_to_collector(self, worker: Worker, collector: Collector, topo: Topology, estimated_rate: float):
        
        graph = topo.graph
    
        # Define a custom weight function for NetworkX that filters out saturated links
        def cspf_weight(u, v, edge_attr):
            link_obj = edge_attr["link"]

            if not link_obj.is_up:
                return float('inf') # Block this edge completely

            if link_obj.residual_bandwidth < estimated_rate:
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
                actions=[ofp_action_output(port=collector.connected_port)],
                idle_timeout=5
            )
            
            log.info(f"Installed path for {worker.ip} -> {collector.ip}: {path}")
            
        except nx.NetworkXNoPath:
            log.warning(f"Traffic bottleneck hit! No available inner fabric paths for worker {worker.ip}")

    def routine_checks(self):
        self.check_residual_capacity()
        self.check_flow()

    def check_flow(self):
        # TODO: check all flows and set ftime when a flow is not used for some time (routine)
        # TODO: check if no data has been sent in this time or update flow.D if data was sent
        
        # NOTE: Idle timeout tracking is now directly handled by the _handle_FlowRemoved event!
        # The switches will automatically notify us 5 seconds after a worker stops sending data.
        self.estimate_flow_data()
        self.estimate_tp_data()

    def _handle_FlowRemoved(self, event):
        # Triggered automatically when an installed flow path goes idle
        match = event.ofp.match
        src_ip = match.nw_src
        
        if src_ip is not None:
            src_ip_str = str(src_ip)
            flow_id = self.worker_to_flow.get(src_ip_str)
            
            if flow_id is not None:
                collector = self.collectors.get(flow_id)
                # Avoid double-counting bytes: only aggregate metrics at the collector's leaf switch
                if collector and event.dpid == collector.connected_to_dpid:
                    tp_id = self.worker_tp_ids.get(src_ip_str)
                    if tp_id is not None:
                        tp = training_procedures[tp_id]
                        flow = next((f for f in tp.flows if f.ID == flow_id), None)
                        if flow:
                            flow.ftime = datetime.now()  # Marks the end of the most recent burst
                            flow.D += event.ofp.byte_count
                            if flow.sTime:
                                flow.completion_time = (flow.ftime - flow.sTime).total_seconds()
                        
                        log.info(f"Worker {src_ip_str} finished burst for TP {tp_id}. Flow bytes: {event.ofp.byte_count}")
                        
                        # Advance worker to the next overlapping TP iteration
                        self.worker_tp_ids[src_ip_str] = tp_id + 1

    def check_residual_capacity(self):
        # TODO: update link residual capacity in graph
        # Send port stats request to all connected switches
        for dpid in self.topology.graph.nodes:
            sw = self.topology.get_switch(dpid)
            if sw and sw.is_connected:
                sw.connection.send(ofp_port_stats_request())
                
    def _handle_PortStatsReceived(self, event):
        dpid = event.dpid
        now = datetime.now()
        
        for stat in event.stats:
            port_no = stat.port_no
            tx_bytes = stat.tx_bytes
            
            key = (dpid, port_no)
            if key in self.port_stats:
                last_bytes, last_time = self.port_stats[key]
                dt = (now - last_time).total_seconds()
                
                if dt > 0:
                    # Calculate bitrate in Mbps
                    bitrate = ((tx_bytes - last_bytes) * 8) / (dt * 1e6)
                    
                    sw = self.topology.get_switch(dpid)
                    if sw and port_no in sw.ports:
                        neighbor_dpid = sw.ports[port_no].neighbor_dpid
                        if neighbor_dpid:
                            link = self.topology.graph[dpid][neighbor_dpid]["link"]
                            link.residual_bandwidth = max(0, link.nominal_bandwidth - bitrate)
                            
            self.port_stats[key] = (tx_bytes, now)

    def estimate_flow_data(self):
        # TODO: estimate the quantities requested in the text for a flow
        for ip, tp_id in self.worker_tp_ids.items():
            if tp_id < len(training_procedures):
                tp = training_procedures[tp_id]
                flow_id = self.worker_to_flow.get(ip)
                flow = next((f for f in tp.flows if f.ID == flow_id), None)
                if flow and flow.sTime and not flow.ftime:
                    uptime = (datetime.now() - flow.sTime).total_seconds()
                    log.info(f"Flow {flow.ID} (Worker {ip}) - TP {tp.id} active for {uptime:.2f}s...")

    def estimate_tp_data(self):
        # TODO: estimate the quantities requested in the text for a training procedure
        # Global training_procedures list imported from data_structures.py
        for tp in training_procedures:
            if not tp.flows:
                continue
            tp.D = sum(flow.D for flow in tp.flows)
            
            # A TP is fully complete if ALL discovered workers have advanced past this TP's ID
            is_completed = all(self.worker_tp_ids.get(ip, 0) > tp.id for ip in self.worker_to_flow)
            
            if is_completed and tp.completion_time == 0:
                start_time = min((flow.sTime for flow in tp.flows if flow.sTime), default=None)
                end_time = max((flow.ftime for flow in tp.flows if flow.ftime), default=None)
                
                if start_time and end_time:
                    tp.completion_time = (end_time - start_time).total_seconds()
                    log.info(f"TP {tp.id} - Completed! D={tp.D} bytes, K={tp.K}, Total Time={tp.completion_time:.2f}s")

def launch():
    log.info("Launching Load Balancer application...")
    LoadBalancer()