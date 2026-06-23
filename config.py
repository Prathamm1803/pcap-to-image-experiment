import os
from dataclasses import dataclass, field
from typing import List, Tuple

@dataclass
class PipelineConfig:
    # Directory Configurations
    input_dir: str = "pcaps"
    output_dir: str = "images"
    csv_log_filename: str = "manifest_summary.csv"
    
    # Packet Filtering Constraints
    min_frame_length: int = 100
    target_protocol: str = "TCP"
    
    # Byte Transformation Configurations
    target_byte_size: int = 784  # 28x28
    image_dimensions: Tuple[int, int] = (28, 28)
    
    # Image Visualization
    scale_factor: int = 50

    # Zero-out index ranges (inclusive, exclusive pairs)
    # Default: 0-11 (MACs) and 26-33 (IPs)
    zero_byte_ranges: List[Tuple[int, int]] = field(
        default_factory=lambda: [(0, 12), (26, 34)]
    )
    
    # Performance Configurations
    # num_workers: int = os.cpu_count() or 1
    num_workers: int = 1


    def __post_init__(self):
        self.csv_log_path = os.path.join(self.output_dir, self.csv_log_filename)