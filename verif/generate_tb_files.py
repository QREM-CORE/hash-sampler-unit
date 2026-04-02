"""
# =============================================================================
# File        : generate_tb_files.py
# Author      : Kiet Le
# Project     : FIPS 203 (ML-KEM / Kyber) Hardware Accelerator
# Description :
#   This script bridges the gap between the Python ML-KEM reference model and
#   the SystemVerilog Hash Sampler Unit (HSU) testbench. It parses a JSON file
#   containing cryptographic test vectors and automatically generates a structured
#   directory tree for automated RTL simulation.
#
# Key Operations:
#   1. Directory Generation : Creates OS-safe, uniquely named folders for each test.
#   2. Config Extraction    : Translates SystemVerilog string Enums into integer
#                             flags (config.txt) for easy $fscanf parsing.
#   3. Expected Output      : Writes 64-bit packed hex strings to expected.hex.
#   4. AXI Byte-Alignment   : Reads the input seed hex, chunks it into 64-bit
#                             words, and performs a Little-Endian byte reversal
#                             to perfectly align with the hardware's AXI4-Stream
#                             t_data[7:0] LSB orientation (input.hex).
#
# Input  : test_vectors.json
# Output : test_vectors/<test_name_id>/ {config.txt, input.hex, expected.hex}
# =============================================================================
"""

import json
import os
import re

# Map your SystemVerilog Enum names to integers so $fscanf can read them easily
MODE_MAP = {
    "MODE_SAMPLE_NTT": 0,
    "MODE_SAMPLE_CBD": 1,
    "MODE_HASH_SHA3_256": 2,
    "MODE_HASH_SHA3_512": 3,
    "MODE_HASH_SHAKE256": 4
}

def generate_files(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    # Create root directory
    root_dir = "test_vectors"
    os.makedirs(root_dir, exist_ok=True)

    for test in data['tests']:
        # Create a highly descriptive, OS-safe folder name
        # e.g., "Test B" + "CBD Sampler Vectors (eta=2)" -> "test_b_cbd_sampler_vectors_eta_2"
        raw_name = f"{test['test_id']}_{test['name']}"
        folder_name = re.sub(r'[^a-zA-Z0-9]+', '_', raw_name.lower()).strip('_')

        test_dir = os.path.join(root_dir, folder_name)
        os.makedirs(test_dir, exist_ok=True)

        print(f"Generating files in {test_dir}/...")

        # 1. Extract Config
        config = test.get('config', {})
        hsu_mode_str = config.get('hsu_mode_i', 'MODE_HASH_SHA3_256')
        hsu_mode_int = MODE_MAP.get(hsu_mode_str, 0)
        is_eta3 = config.get('is_eta3_i', 0)

        in_bytes = len(test['input_seed_hex']) // 2
        out_chunks = len(test['output_beats'])

        # Write config.txt
        with open(os.path.join(test_dir, 'config.txt'), 'w') as f:
            f.write(f"MODE={hsu_mode_int}\n")
            f.write(f"IS_ETA3={is_eta3}\n")
            f.write(f"IN_BYTES={in_bytes}\n")
            f.write(f"OUT_CHUNKS={out_chunks}\n")

        # 2. Write expected.hex (Direct copy from JSON)
        with open(os.path.join(test_dir, 'expected.hex'), 'w') as f:
            for beat in test['output_beats']:
                f.write(f"{beat}\n")

        # 3. Write input.hex (Requires Little-Endian alignment for AXI bus)
        input_hex = test['input_seed_hex']

        # Split into a list of 2-character bytes
        byte_list = [input_hex[i:i+2] for i in range(0, len(input_hex), 2)]

        with open(os.path.join(test_dir, 'input.hex'), 'w') as f:
            # Iterate through the bytes 8 at a time (64 bits)
            for i in range(0, len(byte_list), 8):
                chunk = byte_list[i:i+8]

                # Zero-pad the last chunk if it's not a full 8 bytes
                while len(chunk) < 8:
                    chunk.append('00')

                # Reverse the byte array so Byte 0 is on the far right (LSB)
                chunk.reverse()

                # Join back into a 16-character hex string and write
                f.write("".join(chunk) + "\n")

    print("\nPre-processing complete! All folders and .hex files generated.")

if __name__ == "__main__":
    generate_files("test_vectors.json")
