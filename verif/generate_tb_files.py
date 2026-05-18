"""
# =============================================================================
# File        : generate_tb_files.py
# Author      : Kiet Le
# Project     : FIPS 203 (ML-KEM / Kyber) Hardware Accelerator
# Description :
#   Parses test_vectors.json and generates structured directory trees for
#   automated RTL simulation of the Hash Sampler Unit (HSU).
#
# Key Operations:
#   1. Directory Generation : Creates OS-safe, uniquely named folders per test.
#   2. Config Extraction    : Translates SV enum strings into integer flags
#                             (config.txt) for $fscanf parsing.
#   3. Expected Output      : Writes 64-bit packed hex strings to expected.hex.
#   4. Input Generation     :
#      - Seed/hash modes    : Chunks input seed into 64-bit LE words (input.hex).
#      - MODE_ABSORB_POLY   : Writes 64-bit packed coefficient beats where each
#                             line holds 4 raw 12-bit coefficients:
#                             {coeff[3][11:0], coeff[2][11:0], coeff[1][11:0], coeff[0][11:0]}
#
# Input  : test_vectors.json
# Output : test_vectors/<test_name_id>/ {config.txt, input.hex, expected.hex}
# =============================================================================
"""

import json
import os
import re

MODE_MAP = {
    "MODE_SAMPLE_NTT":    0,
    "MODE_SAMPLE_CBD":    1,
    "MODE_HASH_SHA3_256": 2,
    "MODE_HASH_SHA3_512": 3,
    "MODE_HASH_SHAKE256": 4,
    "MODE_ABSORB_POLY":   5,
}

def generate_files(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    root_dir = "test_vectors"
    os.makedirs(root_dir, exist_ok=True)

    for test in data['tests']:
        raw_name = f"{test['test_id']}_{test['name']}"
        folder_name = re.sub(r'[^a-zA-Z0-9]+', '_', raw_name.lower()).strip('_')
        test_dir = os.path.join(root_dir, folder_name)
        os.makedirs(test_dir, exist_ok=True)
        print(f"Generating files in {test_dir}/...")

        config  = test.get('config', {})
        hsu_mode_str = config.get('hsu_mode_i', 'MODE_HASH_SHA3_256')
        hsu_mode_int = MODE_MAP.get(hsu_mode_str, 0)
        is_eta3      = config.get('is_eta3_i', 0)
        poly_cnt     = config.get('poly_cnt', 1)
        row          = config.get('ROW', 0)
        col          = config.get('COL', 0)
        cbd_n        = config.get('CBD_N', 0)
        run_g_first  = config.get('RUN_G_FIRST', 0)
        input_sel    = config.get('INPUT_SEL', 0)
        xof_len      = config.get('XOF_LEN', 0)
        out_chunks   = len(test['output_beats'])

        # ── Generate expected.hex ──────────────────────────────────────────
        with open(os.path.join(test_dir, 'expected.hex'), 'w') as f:
            for beat in test['output_beats']:
                f.write(f"{beat}\n")

        # ── Generate config.txt & input.hex ───────────────────────────────
        if hsu_mode_str == "MODE_ABSORB_POLY":
            # Coefficient beats: each entry in 'input_coeffs' is a list of 4 ints
            # Stored as 64-bit hex: {16'b0, c3[11:0], c2[11:0], c1[11:0], c0[11:0]}
            coeff_beats = test.get('input_coeffs', [])
            in_words    = len(coeff_beats)

            # Check for optional seed segment (Multi-Phase)
            input_seed_hex = test.get('input_seed_hex', '')
            seed_words     = (len(input_seed_hex) // 2 + 7) // 8
            byte_list      = [input_seed_hex[i:i+2] for i in range(0, len(input_seed_hex), 2)]

            with open(os.path.join(test_dir, 'config.txt'), 'w') as f:
                f.write(f"MODE {hsu_mode_int}\n")
                f.write(f"IS_ETA3 0\n")
                f.write(f"IN_WORDS {in_words}\n")
                f.write(f"SEED_WORDS {seed_words}\n")
                f.write(f"OUT_CHUNKS {out_chunks}\n")
                f.write(f"POLY_CNT {poly_cnt}\n")
                f.write(f"ROW {row}\n")
                f.write(f"COL {col}\n")
                f.write(f"CBD_N {cbd_n}\n")
                f.write(f"RUN_G_FIRST {run_g_first}\n")
                f.write(f"XOF_LEN {xof_len}\n")

            with open(os.path.join(test_dir, 'input.hex'), 'w') as f:
                # 1. Poly coefficients
                for beat in coeff_beats:
                    # beat = [c0, c1, c2, c3]
                    packed = 0
                    for j, c in enumerate(beat):
                        packed |= (int(c) & 0xFFF) << (12 * j)
                    f.write(f"{packed:016X}\n")
                # 2. Seed data (if any)
                for i in range(0, len(byte_list), 8):
                    chunk = byte_list[i:i+8]
                    while len(chunk) < 8: chunk.append('00')
                    chunk.reverse()
                    f.write("".join(chunk) + "\n")

        else:
            # Seed/hash modes: AXI byte-aligned LE words
            input_hex = test.get('input_seed_hex', '')
            in_bytes  = len(input_hex) // 2
            byte_list = [input_hex[i:i+2] for i in range(0, len(input_hex), 2)]
            in_words  = (in_bytes + 7) // 8

            with open(os.path.join(test_dir, 'config.txt'), 'w') as f:
                f.write(f"MODE {hsu_mode_int}\n")
                f.write(f"IS_ETA3 {is_eta3}\n")
                f.write(f"IN_WORDS {in_words}\n")
                f.write(f"OUT_CHUNKS {out_chunks}\n")
                f.write(f"POLY_CNT 1\n")
                f.write(f"ROW {row}\n")
                f.write(f"COL {col}\n")
                f.write(f"CBD_N {cbd_n}\n")
                f.write(f"RUN_G_FIRST {run_g_first}\n")
                f.write(f"INPUT_SEL {input_sel}\n")
                f.write(f"XOF_LEN {xof_len}\n")
                sigma_expected = test.get('sigma_expected', '')

            if sigma_expected:
                with open(os.path.join(test_dir, 'sigma.hex'), 'w') as sf:
                    sf.write(f"{sigma_expected}\n")
            with open(os.path.join(test_dir, 'input.hex'), 'w') as f:
                for i in range(0, len(byte_list), 8):
                    chunk = byte_list[i:i+8]
                    while len(chunk) < 8:
                        chunk.append('00')
                    chunk.reverse()
                    f.write("".join(chunk) + "\n")

    print("\nPre-processing complete! All folders and .hex files generated.")

if __name__ == "__main__":
    generate_files("test_vectors.json")
