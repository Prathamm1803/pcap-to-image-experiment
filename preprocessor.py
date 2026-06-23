from typing import List, Tuple

class PacketPreprocessor:
    def __init__(self, config):
        self.config = config

    def apply_mask(self, raw_bytes: bytes) -> bytearray:
        """Zeroes out sensitive protocol identifier blocks (e.g., MAC & IP spaces)."""
        byte_arr = bytearray(raw_bytes)
        arr_len = len(byte_arr)
        
        for start, end in self.config.zero_byte_ranges:
            if start < arr_len:
                actual_end = min(end, arr_len)
                for i in range(start, actual_end):
                    byte_arr[i] = 0x00
        return byte_arr

    def enforce_fixed_size(self, byte_arr: bytearray) -> bytes:
        """Truncates or zero-pads data buffer strictly to the target dimensions."""
        target = self.config.target_byte_size
        current_len = len(byte_arr)
        
        print(f"Packet length before processing: {current_len}")
        
        if current_len >= target:
            return bytes(byte_arr[:target])
        else:
            return bytes(byte_arr + bytearray(target - current_len))

    def process(self, raw_bytes: bytes) -> bytes:
        """Pipeline orchestration step for data scrubbing and payload normalization."""
        masked = self.apply_mask(raw_bytes)
        return self.enforce_fixed_size(masked)