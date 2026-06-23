import logging
from typing import Generator, Dict, Tuple, Optional
from scapy.all import PcapReader, IP, TCP

logger = logging.getLogger(__name__)

class PacketExtractor:
    def __init__(self, config):
        self.config = config

    def _get_flow_key(self, pkt) -> Optional[Tuple[str, int, str, int]]:
        """Extracts a normalized 4-tuple key to trace the connection flow."""
        if IP in pkt and TCP in pkt:
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
            # Normalize direction so both sides map to the same flow ID tracking
            if (src_ip, src_port) > (dst_ip, dst_port):
                return (dst_ip, dst_port, src_ip, src_port)
            return (src_ip, src_port, dst_ip, dst_port)
        return None

    def extract_packets(self, pcap_path: str) -> Generator[Dict, None, None]:
        """Iteratively processes packet streams from a PCAP file without ram bloating."""
        flow_tracker: Dict[Tuple[str, int, str, int], int] = {}
        flow_counter = 1
        
        try:
            with PcapReader(pcap_path) as reader:
                for packet_idx, pkt in enumerate(reader):
                    # Filter step 1: Size check (corresponds to frame.len)
                    if len(pkt) <= self.config.min_frame_length:
                        continue
                    
                    # Filter step 2: Protocol check
                    if not (IP in pkt and TCP in pkt):
                        continue
                    
                    flow_key = self._get_flow_key(pkt)
                    if not flow_key:
                        continue
                        
                    if flow_key not in flow_tracker:
                        flow_tracker[flow_key] = flow_counter
                        flow_counter += 1
                        
                    print(
                        f"Flow {flow_tracker[flow_key]} | "
                        f"Len={len(pkt)} | "
                        f"Ports={pkt[TCP].sport}->{pkt[TCP].dport}"
)    
                    yield {
                        "packet_index": packet_idx,
                        "flow_number": flow_tracker[flow_key],
                        "src_port": pkt[TCP].sport,
                        "dst_port": pkt[TCP].dport,
                        "raw_bytes": bytes(pkt)
                    }
        except Exception as e:
            logger.error(f"Failed parsing file {pcap_path}: {e}")