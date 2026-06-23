import csv
import logging
import multiprocessing as mp
import os
import sys
import time
from tqdm import tqdm

from config import PipelineConfig
from extractor import PacketExtractor
from preprocessor import PacketPreprocessor
from image_generator import ImageGenerator
from utils import DatasetUtils

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


# def process_single_pcap(pcap_path: str, config: PipelineConfig):
#     """Worker task processing an individual capture file sequentially."""
#     extractor = PacketExtractor(config)
#     preprocessor = PacketPreprocessor(config)
#     generator = ImageGenerator(config)
    
#     target_img_dir, rel_pcap_path = DatasetUtils.compute_relative_paths(
#         config.input_dir, pcap_path, config.output_dir
#     )
    
#     local_records = []
#     processed_count = 0
    
#     for pkt_data in extractor.extract_packets(pcap_path):
#         normalized_bytes = preprocessor.process(pkt_data["raw_bytes"])
        
#         # Match example naming: flow_{flow_num}_{src_port}_{dst_port}.png
#         filename = f"flow_{pkt_data['flow_number']}_{pkt_data['src_port']}_{pkt_data['dst_port']}_{pkt_data['packet_index']}.png"
#         output_file_path = os.path.join(target_img_dir, filename)
        
#         success = generator.bytes_to_png(normalized_bytes, output_file_path)
        
#         if success:
#             processed_count += 1
#             local_records.append({
#                 "source_file": rel_pcap_path,
#                 "flow_number": pkt_data["flow_number"],
#                 "source_port": pkt_data["src_port"],
#                 "destination_port": pkt_data["dst_port"],
#                 "image_filename": os.path.join(os.path.basename(target_img_dir), filename)
#             })
            
#     return pcap_path, processed_count, local_records

def process_single_pcap(pcap_path: str, config: PipelineConfig):
    """Worker task processing an individual capture file sequentially."""
    
    extractor = PacketExtractor(config)
    preprocessor = PacketPreprocessor(config)
    generator = ImageGenerator(config)

    target_img_dir, rel_pcap_path = DatasetUtils.compute_relative_paths(
        config.input_dir,
        pcap_path,
        config.output_dir
    )

    local_records = []
    processed_count = 0

    for pkt_data in extractor.extract_packets(pcap_path):

        print(
            f"Flow={pkt_data['flow_number']} | "
            f"Ports={pkt_data['src_port']}->{pkt_data['dst_port']} | "
            f"Length={len(pkt_data['raw_bytes'])}"
        )

        normalized_bytes = preprocessor.process(
            pkt_data["raw_bytes"]
        )

        filename = (
            f"flow_{pkt_data['flow_number']}_"
            f"{pkt_data['src_port']}_"
            f"{pkt_data['dst_port']}.png"
        )

        output_file_path = os.path.join(
            target_img_dir,
            filename
        )

        success = generator.bytes_to_png(
            normalized_bytes,
            output_file_path
        )

        if success:
            processed_count += 1

            local_records.append({
                "source_file": rel_pcap_path,
                "flow_number": pkt_data["flow_number"],
                "source_port": pkt_data["src_port"],
                "destination_port": pkt_data["dst_port"],
                "image_filename": os.path.join(
                    os.path.basename(target_img_dir),
                    filename
                )
            })

        # TESTING LIMIT
        if processed_count >= 5:
            print("Stopping after 5 samples (test mode)")
            break

    return pcap_path, processed_count, local_records

def main():
    config = PipelineConfig()
    
    print("====================================================")
    print("  Automated Network Traffic Image Pipeline Started   ")
    print("====================================================")
    
    pcap_files = DatasetUtils.discover_pcap_files(config.input_dir)
    print("Discovered files:")
    for f in pcap_files:
        print(f)
    # TEST MODE
    pcap_files = pcap_files[:1]
    
    if not pcap_files:
        logger.error(f"No valid capture records discovered inside: '{config.input_dir}/'. Execution halted.")
        return

    logger.info(f"Discovered {len(pcap_files)} file targets. Executing jobs via {config.num_workers} processes...")
    os.makedirs(config.output_dir, exist_ok=True)

    global_manifest = []
    total_images_generated = 0
    start_time = time.time()

    # Multiprocessing Management Engine
    # with mp.Pool(processes=config.num_workers) as pool:
    #     # Wrap execution mapping loop around high-fidelity tracking bars
    #     async_results = [pool.apply_async(process_single_pcap, args=(f, config)) for f in pcap_files]
        
    #     for result in tqdm(async_results, desc="Processing Datasets", unit="file"):
    #         pcap, count, records = result.get()
    #         total_images_generated += count
    #         global_manifest.extend(records)

    for pcap_file in pcap_files:
        pcap, count, records = process_single_pcap(
            pcap_file,
            config
        )

        total_images_generated += count
        global_manifest.extend(records)

    # Export Manifest Document Summary 
    if global_manifest:
        fieldnames = ["source_file", "flow_number", "source_port", "destination_port", "image_filename"]
        with open(config.csv_log_path, mode="w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(global_manifest)
            
    elapsed = time.time() - start_time
    
    # Dataset Summary Metrics Screen
    print("\n" + "="*52)
    print("                 EXECUTION METRICS                  ")
    print("="*52)
    print(f" Total Target Captures Evaluated : {len(pcap_files)}")
    print(f" Total PNG Images Rendered       : {total_images_generated}")
    print(f" Global Manifest Report Exported : {config.csv_log_path}")
    print(f" Elapsed Processing Time         : {elapsed:.2f} seconds")
    print("="*52 + "\n")


if __name__ == "__main__":
    # Prevent Windows spawning loops
    mp.freeze_support()
    main()