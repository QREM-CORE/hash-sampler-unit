# ML-KEM Hash-Sampler Unit

This repository contains the SystemVerilog implementation of a unified Hash-Sampler Unit, designed specifically for hardware acceleration of the ML-KEM post-quantum cryptography algorithm.

By tightly coupling the cryptographic hashing core with the polynomial samplers, this module eliminates the need for large intermediate memory buffers to store squeezed pseudorandom bytes. This architecture allows the sampling process to run in parallel with the Keccak permutations, effectively hiding the sampling latency and streamlining the data path for subsequent Number Theoretic Transform (NTT) computations.

## 📦 Submodules

This top-level unit instantiates and integrates two core modules from the QREM-CORE organization:

* **[keccak-fips202-sv](https://github.com/QREM-CORE/keccak-fips202-sv):** A SystemVerilog implementation of the SHA-3/SHAKE Extendable-Output Functions (XOFs).
* **[poly-samplers](https://github.com/QREM-CORE/poly-samplers):** Contains the hardware samplers required for ML-KEM, including the Centered Binomial Distribution (CBD) for noise generation and Rejection Sampling (Parse) for matrix generation.

## 🏗️ Architecture Overview

The integration of these two modules addresses several critical hardware bottlenecks in ML-KEM:

* **Memory Reduction:** Bypasses dedicated Keccak output memory (BRAM) by feeding the pseudorandom byte stream directly into the sampler units.
* **Latency Hiding:** The uniform and CBD sampling times are largely absorbed by the execution of the Keccak-f[1600] permutation.
* **Throughput Regulation:** Utilizes localized FIFO buffering between the Keccak output and the samplers to bridge the gap between Keccak's large burst outputs and the samplers' continuous consumption rates, gracefully handling rejection stalls.
* **Multi-Mode Routing:** Supports routing Keccak outputs either to the samplers (for key and noise generation) or directly to standard registers/memory (for standard message hashing during encapsulation and decapsulation).

## 🚀 Getting Started

### Prerequisites

* A SystemVerilog-compatible simulator (e.g., ModelSim, Verilator, Vivado, Quartus).
* Synthesis toolchain for your target FPGA architecture.

### Cloning the Repository

Because this project relies on Git submodules for the Keccak core and the samplers, you must clone the repository recursively to pull in all the necessary source files:

```bash
git clone --recursive https://github.com/QREM-CORE/hash-sampler-unit.git
cd hash-sampler-unit
```

If you have already cloned the repository without the `--recursive` flag, you can initialize and update the submodules using:

```bash
git submodule update --init --recursive
```
