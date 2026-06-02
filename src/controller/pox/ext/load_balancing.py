from data_structures import *
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import networkx as nx
from datetime import datetime
from pox.lib.recoco import Timer

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

        # --- Rate estimation state ---
        # Maps (dpid, port) -> worker IP for all known worker ingress ports
        self.port_to_worker = {}
        # Maps worker IP -> most recent Mbps estimate (updated by port stats polling)
        self.worker_rates = {}
        # Maps worker IP -> (accumulated_bytes, window_start_time)
        # Used to integrate byte counts seen in FlowRemoved events into a final rate sample.
        self.worker_byte_window: dict[str, tuple[int, datetime]] = {}
        
        Timer(5, self.routine_checks, recurring=True)
        
        self.populate_mappings()
        log.info("LoadBalancer initialized. Recurring checks started.")

    def populate_mappings(self):
        collector1 = Collector(ip="10.0.1.1", flow_id=1, connected_to_dpid=3, connected_port=1)
        collector2 = Collector(ip="10.0.1.2", flow_id=2, connected_to_dpid=3, connected_port=2)
        collector3 = Collector(ip="10.0.1.3", flow_id=3, connected_to_dpid=3, connected_port=3)
        collector4 = Collector(ip="10.0.1.4", flow_id=4, connected_to_dpid=3, connected_port=4)
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
        topo.add_link(Link(src_dpid=1, dst_dpid=101, src_port=11, dst_port=1))
        topo.add_link(Link(src_dpid=1, dst_dpid=102, src_port=12, dst_port=1))
        topo.add_link(Link(src_dpid=2, dst_dpid=101, src_port=9,  dst_port=2))
        topo.add_link(Link(src_dpid=2, dst_dpid=102, src_port=10, dst_port=2))
        topo.add_link(Link(src_dpid=3, dst_dpid=101, src_port=5,  dst_port=3))
        topo.add_link(Link(src_dpid=3, dst_dpid=102, src_port=6,  dst_port=3))
        topo.add_link(Link(src_dpid=4, dst_dpid=101, src_port=7,  dst_port=4))
        topo.add_link(Link(src_dpid=4, dst_dpid=102, src_port=8,  dst_port=4))
        topo.add_link(Link(src_dpid=5, dst_dpid=101, src_port=5,  dst_port=5))
        topo.add_link(Link(src_dpid=5, dst_dpid=102, src_port=6,  dst_port=5))

        return topo

    def _handle_ConnectionUp(self, event):
        # Link the POX connection to our topology model
        sw = self.topology.get_switch(event.dpid)
        if sw:
            sw.connection = event.connection
            sw.is_connected = True
            
        # Proactively flood ARP packets so workers can resolve MAC addresses
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_type=0x0806)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)
        log.info(f"Installed ARP flood rule on switch {event.dpid}")
        
        # Proactively drop IPv6 traffic (keeps logs clean from discovery noise)
        msg_ipv6 = of.ofp_flow_mod()
        msg_ipv6.match = of.ofp_match(dl_type=0x86dd)
        event.connection.send(msg_ipv6)
        
        # Proactively drop DNS (Port 53) and mDNS (Port 5353) to prevent POX parsing bugs
        for port in [53, 5353]:
            msg_dns = of.ofp_flow_mod()
            msg_dns.match = of.ofp_match(dl_type=0x0800, nw_proto=17, tp_dst=port)
            event.connection.send(msg_dns)

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

            # Record the ingress port so port-stats polling can map bytes back to this worker
            self.port_to_worker[(sw_dpid, in_port)] = src_ip
            
            # Learn K (total number of discovered workers)
            tp.K = len(self.worker_to_flow)

            collector = self.collectors.get(flow_id)
            if not collector:
                return # Collector not defined for this flow

            # Use the measured per-worker rate if available; fall back to fair-share estimate.
            # The measured rate is populated by _handle_PortStatsReceived via the ingress port
            # of the worker's leaf switch and is refreshed every 5 s by routine_checks.
            estimated_rate = self._estimate_worker_rate(src_ip, tp.K)

            log.info(
                f"New burst from {src_ip} (Flow {flow_id}, Cycle {tp_id + 1}). "
                f"K={tp.K}, Est Rate={estimated_rate:.2f} Mbps "
                f"({'measured' if src_ip in self.worker_rates else 'fair-share fallback'})"
            )
            
            self.route_worker_to_collector(worker, collector, self.topology, estimated_rate)

            # Re-inject the TCP SYN packet back into the switch so it isn't dropped
            msg = of.ofp_packet_out(buffer_id=event.ofp.buffer_id, in_port=in_port)
            if event.ofp.buffer_id == -1:
                msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=of.OFPP_TABLE))
            event.connection.send(msg)

        # TODO: find data rate and/or install flow rules

    def register_or_update_worker(self, ip: str, dpid: int, port: int, flow: Flow):
        for w in flow.workers:
            if w.ip == ip:
                return None # Suppress duplicate packets within the same burst
                
        # New worker detected!
        new_worker = Worker(ip=ip, flow_id=flow.ID, connected_to_dpid=dpid, connected_port=port)
        flow.workers.append(new_worker)
        
        if flow.sTime is None:
            flow.sTime = datetime.now()
            
        return new_worker

    def _estimate_worker_rate(self, worker_ip: str, K: int) -> float:
        """
        Return the best available Mbps estimate for *worker_ip*.

        Priority order:
          1. A fresh measurement from port-stats polling stored in self.worker_rates.
          2. A rate derived from bytes accumulated in the current byte-count window
             (self.worker_byte_window) — updated on every FlowRemoved event.
          3. A conservative fair-share fallback: link_capacity / K.

        The fair-share value is also used as a hard ceiling so that a single
        misbehaving worker cannot claim more capacity than its fair share.
        """
        fair_share = 100.0 / max(K, 1)

        # 1. Fresh port-stats measurement
        if worker_ip in self.worker_rates:
            measured = self.worker_rates[worker_ip]
            # Cap at fair-share to avoid over-claiming residual bandwidth
            return min(measured, fair_share)

        # 2. Byte-window fallback (coarser, derived from FlowRemoved byte counts)
        if worker_ip in self.worker_byte_window:
            acc_bytes, window_start = self.worker_byte_window[worker_ip]
            elapsed = (datetime.now() - window_start).total_seconds()
            if elapsed > 0:
                rate_mbps = (acc_bytes * 8) / (elapsed * 1e6)
                return min(rate_mbps, fair_share)

        # 3. Pure fair-share
        return fair_share

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
                
            # Install the forward path rules
            topo.install_path(path, match_template=of.ofp_match(dl_type=0x0800, nw_src=worker.ip, nw_dst=collector.ip))
            
            # Install reverse path for TCP return traffic (SYN-ACK)
            reverse_path = path[::-1]
            topo.install_path(reverse_path, match_template=of.ofp_match(dl_type=0x0800, nw_src=collector.ip, nw_dst=worker.ip))
            
            # Don't forget the final hop out of the destination switch to the collector itself!
            dest_sw = topo.get_switch(collector.connected_to_dpid)
            dest_sw.send_flow_mod(
                match=of.ofp_match(dl_type=0x0800, nw_src=worker.ip, nw_dst=collector.ip),
                actions=[of.ofp_action_output(port=collector.connected_port)],
                idle_timeout=5
            )

            # Final hop back out of the source switch to the worker!
            src_sw = topo.get_switch(worker.connected_to_dpid)
            src_sw.send_flow_mod(
                match=of.ofp_match(dl_type=0x0800, nw_src=collector.ip, nw_dst=worker.ip),
                actions=[of.ofp_action_output(port=worker.connected_port)],
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

                            # Feed byte count into the per-worker sliding window so
                            # _estimate_worker_rate can produce a rate even before the
                            # first port-stats poll arrives.
                            byte_count = event.ofp.byte_count
                            if src_ip_str in self.worker_byte_window:
                                prev_bytes, window_start = self.worker_byte_window[src_ip_str]
                                self.worker_byte_window[src_ip_str] = (prev_bytes + byte_count, window_start)
                            elif flow.sTime:
                                self.worker_byte_window[src_ip_str] = (byte_count, flow.sTime)
                        
                        log.info(f"Worker {src_ip_str} finished burst for Cycle {tp_id + 1}. Flow bytes: {event.ofp.byte_count}")

                        # Advance worker to the next overlapping TP iteration
                        self.worker_tp_ids[src_ip_str] = tp_id + 1

                        # Reset the byte window so the next cycle starts fresh
                        self.worker_byte_window.pop(src_ip_str, None)

    def check_residual_capacity(self):
        # TODO: update link residual capacity in graph
        # Send port stats request to all connected switches
        for dpid in self.topology.graph.nodes:
            sw = self.topology.get_switch(dpid)
            if sw and sw.is_connected:
                msg = of.ofp_stats_request(body=of.ofp_port_stats_request())
                sw.connection.send(msg)
                
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

                    # 1. Update the link's residual bandwidth
                    sw = self.topology.get_switch(dpid)
                    if sw and port_no in sw.ports:
                        neighbor_dpid = sw.ports[port_no].neighbor_dpid
                        if neighbor_dpid:
                            link = self.topology.graph[dpid][neighbor_dpid]["link"]
                            link.residual_bandwidth = max(0, link.nominal_bandwidth - bitrate)

                    # 2. If this port is the ingress of a known worker, store a fresh rate sample.
                    #    The ingress port *receives* the worker's traffic, so we use rx_bytes
                    #    (stat.rx_bytes) for the worker's send rate and tx_bytes for the link's
                    #    outgoing utilisation.  Here we reuse `bitrate` (tx side) as a proxy when
                    #    rx_bytes is unavailable; adjust if your OVS version exposes rx_bytes.
                    worker_ip = self.port_to_worker.get((dpid, port_no))
                    if worker_ip is not None:
                        self.worker_rates[worker_ip] = bitrate
                        log.debug(
                            f"Rate sample for worker {worker_ip}: {bitrate:.2f} Mbps "
                            f"(port {port_no} on dpid {dpid})"
                        )
                            
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
                    log.info(f"Flow {flow.ID} (Worker {ip}) - Cycle {tp.id + 1} active for {uptime:.2f}s...")

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
                    log.info(f"Cycle {tp.id + 1} - Completed! Total bytes: {tp.D}, Active Workers K={tp.K}, Time={tp.completion_time:.2f}s")

def launch():
    log.info("Launching Load Balancer application...")
    LoadBalancer()