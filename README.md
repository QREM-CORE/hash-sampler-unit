# ML-KEM Hash-Sampler Unit (HSU)

[![Build Status](https://github.com/QREM-CORE/hash-sampler-unit/actions/workflows/pr.yml/badge.svg)](https://github.com/QREM-CORE/hash-sampler-unit/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Standard: FIPS 203](https://img.shields.io/badge/Standard-FIPS%20203-blue.svg)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)

The **Hash-Sampler Unit (HSU)** is a high-performance hardware accelerator core designed to perform the cryptographic hashing and polynomial sampling operations required by **ML-KEM (FIPS 203)**. 

By tightly coupling a **1-cycle-per-round Keccak engine** with specialized **Rejection (NTT)** and **Centered Binomial Distribution (CBD)** samplers, this unit eliminates the need for large intermediate memory buffers and significantly reduces total system latency for matrix and vector generation.

---

## 🏗️ Architecture Overview

The HSU features a dynamic demux/mux routing architecture that allows the Keccak output stream to either feed the samplers directly or bypass them for standard SHA3/SHAKE hashing.

```mermaid
graph LR
    subgraph HSU["Hash-Sampler Unit (HSU)"]
        direction LR
        S_AXI["AXI-S Sink (In)"] --> KCORE["Keccak Core<br/>(1-Cycle Round)"]
        KCORE --> DMUX["Routing Demux"]
        DMUX -- SHAKE128 --> NTT["Sample NTT<br/>(Rejection)"]
        DMUX -- SHAKE256 --> CBD["Sample CBD<br/>(η=2,3)"]
        DMUX -- Bypass --> MUX["Output Mux"]
        NTT --> MUX
        CBD --> MUX
        MUX --> M_AXI["AXI-S Source (Out)"]
    end

    %% Premium Hardware Styling
    classDef io fill:#f5f5f5,stroke:#263238,color:#212121,font-weight:bold;
    classDef core fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20,font-weight:bold;
    classDef router fill:#e3f2fd,stroke:#1565c0,color:#0d47a1,font-weight:bold;
    classDef sampler fill:#fffde7,stroke:#f9a825,color:#f57f17,font-weight:bold;
    classDef hsu fill:none,stroke:#90a4ae,stroke-width:2px,stroke-dasharray: 5 5;

    class S_AXI,M_AXI io;
    class KCORE core;
    class DMUX,MUX router;
    class NTT,CBD sampler;
    class HSU hsu;
```

### Key Technical Specs:
- **Keccak Engine**: Fully compliant FIPS 202 permutation core (SHA3-256/512, SHAKE128/256).
- **NTT Sampler**: Hardware-accelerated rejection sampler (Algorithm 7). Produces 256 coefficients indexed by AXI-S `t_last`.
- **CBD Sampler**: Unified η=2/3 sampler (Algorithm 8). Configurable at runtime via `is_eta3_i`.
- **Interface**: Standard AXI4-Stream (64-bit) logic for easy integration into SoC fabrics.
- **Latency Hiding**: Parallelizing Keccak "squeezing" with sampling logic to saturate the output data path.

---

## ⚙️ Operational Modes (`hsu_mode_i`)

The unit assumes one of five primary modes defined in `hash_sample_pkg::hs_mode_t`:

| Enum Name | Keccak Op | Sampler Layer | Security (η) | ML-KEM Operation |
| :--- | :--- | :--- | :--- | :--- |
| `MODE_SAMPLE_NTT` | SHAKE128 | Rejection | N/A | **Matrix A** Generation |
| `MODE_SAMPLE_CBD` | SHAKE256 | CBD | η=2 or η=3 | **s, e, e1, e2** Generation |
| `MODE_HASH_SHA3_256` | SHA3-256 | Bypass | N/A | Hash functions **H(p, m, c)** |
| `MODE_HASH_SHA3_512` | SHA3-512 | Bypass | N/A | Hash functions **G(d, m, h)** |
| `MODE_HASH_SHAKE256` | SHAKE256 | Bypass | N/A | Function **J(z, c)** |

> [!NOTE]
> Sampler outputs are 48-bit (4 x 12-bit coeffs) which are zero-padded to 64-bit `t_data_o`: `{16'b0, data[47:0]}`.

---

## 📟 Interface Description

### Control & Status
- **`start_i`**: Pulse (1 cycle) to begin a hashing/sampling operation.
- **`hsu_mode_i`**: Selects routing and hashing parameters. Must be stable on `start_i`.
- **`is_eta3_i`**: (CBD Only) Set to `1` for ML-KEM-768/1024, `0` for ML-KEM-512.
- **`xof_len_i`**: Defines total output bytes for SHAKE modes (0 = infinite/continuous).

### AXI4-Stream Ports
| Port | Direction | Width | Description |
| :--- | :--- | :--- | :--- |
| `t_data_i` | Sink | 64-bit | Input data (message/prefix) |
| `t_valid_i` | Sink | 1-bit | Input valid |
| `t_ready_o` | Sink | 1-bit | HSU ready to accept input |
| `t_data_o` | Source | 64-bit | Output (Hash or 4x Coeffs) |
| `t_valid_o` | Source | 1-bit | Output valid |
| `t_ready_i` | Source | 1-bit | Downstream backpressure |
| `t_last_o` | Source | 1-bit | Marks end of hash or 256th coeff |

---

## 🚀 Getting Started

### Prerequisites
- SystemVerilog compatible simulator (Verilator 5.0+, ModelSim, Vivado).
- Python 3.x for test vector generation.

### Installation
```bash
# Clone recursively to include Keccak and Sampler submodules
git clone --recursive https://github.com/QREM-CORE/hash-sampler-unit.git
cd hash-sampler-unit
```

### Verification
The verification suite uses a Python-driven flow to generate vectors and run the SystemVerilog testbench.

```bash
# Generate test vectors and run all testcases in Verilator
make run_hash_sampler_unit_tb SIM=verilator

# To run with ModelSim
make run_hash_sampler_unit_tb SIM=modelsim
```

---

## 📦 Submodules
This project integrates high-performance cores from the **QREM-CORE** library:
*   [keccak-fips202-sv](https://github.com/QREM-CORE/keccak-fips202-sv): 1-cycle-per-round Keccak core.
*   [poly-samplers](https://github.com/QREM-CORE/poly-samplers): High-throughput CBD and NTT sampling units.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
