import os
from typing import List, Tuple

class DatasetUtils:
    @staticmethod
    def discover_pcap_files(input_dir: str) -> List[str]:
        """Recursively parses input targets capturing valid capture extensions."""
        target_extensions = ('.pcap', '.pcapng')
        discovered = []
        for root, _, files in os.walk(input_dir):
            for file in files:
                if file.lower().endswith(target_extensions):
                    discovered.append(os.path.join(root, file))
        return sorted(discovered)

    @staticmethod
    def compute_relative_paths(input_dir: str, pcap_path: str, output_dir: str) -> Tuple[str, str]:
        """Calculates mirrored folder hierarchies matching specific layout patterns."""
        rel_path = os.path.relpath(pcap_path, input_dir)
        rel_dir, filename = os.path.split(rel_path)
        base_name = os.path.splitext(filename)[0]
        
        # Mirror placement folder structure
        target_img_dir = os.path.join(output_dir, rel_dir, base_name)
        return target_img_dir, rel_path