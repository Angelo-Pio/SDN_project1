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
        self.worker_tp_ids = {}     # Maps worker IP -> current tp_id (int)

        # --- Port stats tracking ---
        # Maps (dpid, port, 'tx'|'rx') -> (last_bytes, last_timestamp)
        self.port_stats = {}
        # Maps (dpid, port) -> worker IP for all known worker ingress ports
        self.port_to_worker = {}

        # --- Rate estimation state ---
        # Maps worker IP -> most recent Mbps estimate (from rx_bytes on ingress port)
        self.worker_rates = {}
        # Maps worker IP -> (accumulated_bytes, window_start_time)
        # Fed by FlowRemoved byte counts; used as fallback when port-stats haven't
        # returned a measurement yet.
        self.worker_byte_window: dict[str, tuple[int, datetime]] = {}

        # --- Path bookkeeping (needed to restore residual BW on FlowRemoved) ---
        # Maps worker IP -> list of DPIDs on the installed forward path
        self.worker_path: dict[str, list[int]] = {}

        # FIX #5: poll every 2 s (was 5 s) so short bursts aren't missed.
        # The flow idle_timeout stays at 5 s; we now get at least 2 samples
        # before a flow expires.
        Timer(2, self.routine_checks, recurring=True)
        
        self.populate_mappings()
        log.info("LoadBalancer initialized. Recurring checks started.")

    # ------------------------------------------------------------------ #
    # Static topology / mapping setup                                      #
    # ------------------------------------------------------------------ #

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

    # ------------------------------------------------------------------ #
    # OpenFlow event handlers                                              #
    # ------------------------------------------------------------------ #

    def _handle_ConnectionUp(self, event):
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
        
        # Proactively drop IPv6 traffic
        msg_ipv6 = of.ofp_flow_mod()
        msg_ipv6.match = of.ofp_match(dl_type=0x86dd)
        event.connection.send(msg_ipv6)
        
        # Proactively drop DNS (Port 53) and mDNS (Port 5353)
        for port in [53, 5353]:
            msg_dns = of.ofp_flow_mod()
            msg_dns.match = of.ofp_match(dl_type=0x0800, nw_proto=17, tp_dst=port)
            event.connection.send(msg_dns)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        ip_packet = packet.find('ipv4')
        if ip_packet is not None:
            src_ip = str(ip_packet.srcip)
            dst_ip = str(ip_packet.dstip)
            in_port = event.port
            sw_dpid = event.dpid

            flow_id = self.worker_to_flow.get(src_ip)
            if flow_id is None:
                for id, collector in self.collectors.items():
                    if collector.ip == dst_ip:
                        flow_id = id
                        break
            if flow_id is None:
                return

            self.worker_to_flow[src_ip] = flow_id

            tp_id = self.worker_tp_ids.setdefault(src_ip, 0)

            while len(training_procedures) <= tp_id:
                training_procedures.append(TrainingProcedure(id=len(training_procedures)))
                
            tp = training_procedures[tp_id]

            flow = next((f for f in tp.flows if f.ID == flow_id), None)
            if flow is None:
                collector = self.collectors.get(flow_id)
                flow = Flow(ID=flow_id, collector=collector)
                tp.flows.append(flow)
                
            worker = self.register_or_update_worker(src_ip, sw_dpid, in_port, flow)
            if not worker:
                return

            # Register ingress port so port-stats polling maps rx_bytes to this worker
            self.port_to_worker[(sw_dpid, in_port)] = src_ip
            
            tp.K = len(self.worker_to_flow)

            collector = self.collectors.get(flow_id)
            if not collector:
                return

            estimated_rate = self._estimate_worker_rate(src_ip, tp.K)

            log.info(
                f"New burst starting from {src_ip} (Flow {flow_id}, Cycle {tp_id + 1}). "
                f"Initial path allocated at {estimated_rate:.2f} Mbps "
                f"({'historical' if src_ip in self.worker_rates else 'fair-share fallback'})"
            )
            
            self.route_worker_to_collector(worker, collector, self.topology, estimated_rate)

            # FIX #2: request port stats immediately after path installation so
            # the first real measurement arrives as quickly as possible (without
            # waiting for the next timer tick).
            self._request_port_stats_from(sw_dpid)

            # Re-inject the original packet so it isn't dropped
            msg = of.ofp_packet_out(buffer_id=event.ofp.buffer_id, in_port=in_port)
            if event.ofp.buffer_id == -1:
                msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=of.OFPP_TABLE))
            event.connection.send(msg)

    def _handle_FlowRemoved(self, event):
        match = event.ofp.match
        src_ip = match.nw_src
        
        if src_ip is not None:
            src_ip_str = str(src_ip)
            flow_id = self.worker_to_flow.get(src_ip_str)
            
            if flow_id is not None:
                collector = self.collectors.get(flow_id)
                # Avoid double-counting: only aggregate at the collector's leaf switch
                if collector and event.dpid == collector.connected_to_dpid:
                    tp_id = self.worker_tp_ids.get(src_ip_str)
                    if tp_id is not None:
                        tp = training_procedures[tp_id]
                        flow = next((f for f in tp.flows if f.ID == flow_id), None)
                        if flow:
                            flow.ftime = datetime.now()
                            flow.D += event.ofp.byte_count

                            # The switch waits before sending FlowRemoved. We subtract this idle 
                            # time using hardware timers to get the exact active duration.
                            total_duration = event.ofp.duration_sec + (event.ofp.duration_nsec / 1e9)
                            idle_time = event.ofp.idle_timeout if event.ofp.reason == of.OFPRR_IDLE_TIMEOUT else 0
                            active_time = max(0.01, total_duration - idle_time)
                            flow.completion_time = active_time

                            # Feed byte count into the per-worker sliding window so
                            # _estimate_worker_rate can use it as a fallback on the
                            # next cycle before the first port-stats poll arrives.
                            byte_count = event.ofp.byte_count
                            if src_ip_str in self.worker_byte_window:
                                prev_bytes, window_start = self.worker_byte_window[src_ip_str]
                                self.worker_byte_window[src_ip_str] = (prev_bytes + byte_count, window_start)
                            elif flow.sTime:
                                self.worker_byte_window[src_ip_str] = (byte_count, flow.sTime)

                            # Store the highly accurate hardware-based rate
                            if byte_count > 0:
                                burst_rate = (byte_count * 8) / (active_time * 1e6)
                                self.worker_rates[src_ip_str] = burst_rate
                                log.info(
                                    f"[FINAL RATE] {src_ip_str} completed burst: "
                                    f"{burst_rate:.2f} Mbps over {active_time:.2f}s active time"
                                )

                        log.info(
                            f"Worker {src_ip_str} finished burst for Cycle {tp_id + 1}. "
                            f"Flow bytes: {event.ofp.byte_count}"
                        )

                        # FIX #3: restore residual bandwidth along the path that was
                        # just torn down so future routing decisions see accurate values.
                        self._restore_residual_bandwidth(src_ip_str, tp.K)

                        # Advance worker to the next overlapping TP iteration
                        self.worker_tp_ids[src_ip_str] = tp_id + 1

                        # Reset the byte window so the next cycle starts fresh
                        self.worker_byte_window.pop(src_ip_str, None)

    def _handle_PortStatsReceived(self, event):
        dpid = event.dpid
        now = datetime.now()
        
        for stat in event.stats:
            port_no = stat.port_no

            # --- Link utilisation: track tx_bytes on each outgoing port ---
            tx_key = (dpid, port_no, 'tx')
            tx_bytes = stat.tx_bytes
            if tx_key in self.port_stats:
                last_tx, last_time = self.port_stats[tx_key]
                dt = (now - last_time).total_seconds()
                if dt > 0:
                    tx_bitrate = ((tx_bytes - last_tx) * 8) / (dt * 1e6)
                    sw = self.topology.get_switch(dpid)
                    if sw and port_no in sw.ports:
                        neighbor_dpid = sw.ports[port_no].neighbor_dpid
                        if neighbor_dpid and self.topology.graph.has_edge(dpid, neighbor_dpid):
                            link = self.topology.graph[dpid][neighbor_dpid]["link"]
                            link.residual_bandwidth = max(0.0, link.nominal_bandwidth - tx_bitrate)
            self.port_stats[tx_key] = (tx_bytes, now)

            # FIX #1: use rx_bytes (traffic *received* from the worker) to estimate
            # the worker's actual send rate, not tx_bytes (outgoing switch traffic).
            rx_key = (dpid, port_no, 'rx')
            rx_bytes = stat.rx_bytes
            if rx_key in self.port_stats:
                last_rx, last_time = self.port_stats[rx_key]
                dt = (now - last_time).total_seconds()
                if dt > 0:
                    rx_bitrate = ((rx_bytes - last_rx) * 8) / (dt * 1e6)
                    worker_ip = self.port_to_worker.get((dpid, port_no))
                    if worker_ip is not None:
                        # Only record and log if there is actual traffic, avoiding 0.0 overwrites
                        if rx_bitrate > 0.1:
                            self.worker_rates[worker_ip] = rx_bitrate
                            log.info(
                                f"[LIVE RATE] Worker {worker_ip} is actively transmitting at "
                                f"{rx_bitrate:.2f} Mbps"
                            )
            self.port_stats[rx_key] = (rx_bytes, now)

    # ------------------------------------------------------------------ #
    # Worker registration                                                  #
    # ------------------------------------------------------------------ #

    def register_or_update_worker(self, ip: str, dpid: int, port: int, flow: Flow):
        for w in flow.workers:
            if w.ip == ip:
                return None  # Suppress duplicate packets within the same burst
                
        new_worker = Worker(ip=ip, flow_id=flow.ID, connected_to_dpid=dpid, connected_port=port)
        flow.workers.append(new_worker)
        
        if flow.sTime is None:
            flow.sTime = datetime.now()
            
        return new_worker

    # ------------------------------------------------------------------ #
    # Rate estimation                                                      #
    # ------------------------------------------------------------------ #

    def _estimate_worker_rate(self, worker_ip: str, K: int) -> float:
        """
        Return the best available Mbps estimate for *worker_ip*.

        Priority order:
          1. A fresh measurement from port-stats polling (rx_bytes on ingress port),
             or a burst-derived rate stored at FlowRemoved time. Both live in
             self.worker_rates and are more accurate than any fallback.
          2. A rate derived from bytes accumulated in the current byte-count window
             (self.worker_byte_window) — updated on every FlowRemoved event.
          3. A conservative fair-share fallback: link_capacity / K.

        FIX #4: the measured rate is no longer capped at fair_share. Heavy workers
        are logged as warnings in _handle_PortStatsReceived instead.
        """
        fair_share = 100.0 / max(K, 1)

        # 1. Port-stats rx measurement or previous-burst-derived rate
        if worker_ip in self.worker_rates and self.worker_rates[worker_ip] > 0:
            return self.worker_rates[worker_ip]

        # 2. Byte-window fallback (coarser, derived from FlowRemoved byte counts)
        if worker_ip in self.worker_byte_window:
            acc_bytes, window_start = self.worker_byte_window[worker_ip]
            elapsed = (datetime.now() - window_start).total_seconds()
            if elapsed > 0:
                rate_mbps = (acc_bytes * 8) / (elapsed * 1e6)
                return rate_mbps

        # 3. Pure fair-share
        return fair_share

    # ------------------------------------------------------------------ #
    # Routing                                                              #
    # ------------------------------------------------------------------ #

    def route_worker_to_collector(self, worker: Worker, collector: Collector,
                                  topo: Topology, estimated_rate: float):
        graph = topo.graph

        def cspf_weight(u, v, edge_attr):
            link_obj = edge_attr["link"]
            if not link_obj.is_up:
                return float('inf')
            if link_obj.residual_bandwidth < estimated_rate:
                return float('inf')
            utilization = (
                (link_obj.nominal_bandwidth - link_obj.residual_bandwidth)
                / link_obj.nominal_bandwidth
            )
            return 1.0 + utilization

        try:
            path = nx.shortest_path(
                graph,
                source=worker.connected_to_dpid,
                target=collector.connected_to_dpid,
                weight=cspf_weight
            )

            # Deduct used bandwidth along the selected path
            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]
                graph[u][v]["link"].residual_bandwidth -= estimated_rate

            # FIX #3: remember the path so we can restore BW when FlowRemoved fires
            self.worker_path[worker.ip] = path

            # Install forward path rules
            topo.install_path(
                path,
                match_template=of.ofp_match(
                    dl_type=0x0800, nw_src=worker.ip, nw_dst=collector.ip
                )
            )

            # Install reverse path for TCP return traffic
            reverse_path = path[::-1]
            topo.install_path(
                reverse_path,
                match_template=of.ofp_match(
                    dl_type=0x0800, nw_src=collector.ip, nw_dst=worker.ip
                )
            )

            # Final hop: source leaf -> collector
            dest_sw = topo.get_switch(collector.connected_to_dpid)
            dest_sw.send_flow_mod(
                match=of.ofp_match(
                    dl_type=0x0800, nw_src=worker.ip, nw_dst=collector.ip
                ),
                actions=[of.ofp_action_output(port=collector.connected_port)],
                idle_timeout=5
            )

            # Final hop: destination leaf -> worker (reverse)
            src_sw = topo.get_switch(worker.connected_to_dpid)
            src_sw.send_flow_mod(
                match=of.ofp_match(
                    dl_type=0x0800, nw_src=collector.ip, nw_dst=worker.ip
                ),
                actions=[of.ofp_action_output(port=worker.connected_port)],
                idle_timeout=5
            )

            log.info(f"Installed path for {worker.ip} -> {collector.ip}: {path}")

        except nx.NetworkXNoPath:
            log.warning(
                f"Traffic bottleneck hit! No available inner fabric paths "
                f"for worker {worker.ip}"
            )

    # ------------------------------------------------------------------ #
    # Residual bandwidth restoration (FIX #3)                             #
    # ------------------------------------------------------------------ #

    def _restore_residual_bandwidth(self, worker_ip: str, K: int):
        """
        When a flow expires (FlowRemoved), add back the bandwidth that was
        reserved for it along its stored path.  Without this the residual_bandwidth
        values drift downward over time and CSPF eventually finds no valid path.
        """
        path = self.worker_path.pop(worker_ip, None)
        if not path:
            return

        # Use the last measured rate, or fall back to fair-share
        rate = self.worker_rates.get(worker_ip, 100.0 / max(K, 1))

        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            if self.topology.graph.has_edge(u, v):
                link = self.topology.graph[u][v]["link"]
                link.residual_bandwidth = min(
                    link.nominal_bandwidth,
                    link.residual_bandwidth + rate
                )

        log.debug(f"Restored {rate:.2f} Mbps along path {path} for worker {worker_ip}")

    # ------------------------------------------------------------------ #
    # Routine checks                                                       #
    # ------------------------------------------------------------------ #

    def routine_checks(self):
        self.check_residual_capacity()
        self.check_flow()

    def check_flow(self):
        self.estimate_flow_data()
        self.estimate_tp_data()

    def check_residual_capacity(self):
        """Poll port stats on all connected switches."""
        for dpid in self.topology.graph.nodes:
            self._request_port_stats_from(dpid)

    def _request_port_stats_from(self, dpid: int):
        """Send a single port-stats request to the switch identified by *dpid*."""
        sw = self.topology.get_switch(dpid)
        if sw and sw.is_connected:
            msg = of.ofp_stats_request(body=of.ofp_port_stats_request())
            sw.connection.send(msg)

    def estimate_flow_data(self):
        for ip, tp_id in self.worker_tp_ids.items():
            if tp_id < len(training_procedures):
                tp = training_procedures[tp_id]
                flow_id = self.worker_to_flow.get(ip)
                flow = next((f for f in tp.flows if f.ID == flow_id), None)
                if flow and flow.sTime and not flow.ftime:
                    uptime = (datetime.now() - flow.sTime).total_seconds()
                    log.info(
                        f"Flow {flow.ID} (Worker {ip}) - "
                        f"Cycle {tp.id + 1} active for {uptime:.2f}s..."
                    )

    def estimate_tp_data(self):
        for tp in training_procedures:
            if not tp.flows:
                continue
            tp.D = sum(flow.D for flow in tp.flows)

            is_completed = all(
                self.worker_tp_ids.get(ip, 0) > tp.id
                for ip in self.worker_to_flow
            )

            if is_completed and tp.completion_time == 0:
                start_time = min(
                    (flow.sTime for flow in tp.flows if flow.sTime), default=None
                )
                end_time = max(
                    (flow.ftime for flow in tp.flows if flow.ftime), default=None
                )

                if start_time and end_time:
                    tp.completion_time = (end_time - start_time).total_seconds()
                    log.info(
                        f"Cycle {tp.id + 1} - Completed! "
                        f"Total bytes: {tp.D}, Active Workers K={tp.K}, "
                        f"Time={tp.completion_time:.2f}s"
                    )


def launch():
    log.info("Launching Load Balancer application...")
    LoadBalancer()