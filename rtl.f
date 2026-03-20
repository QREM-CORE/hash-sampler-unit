# --- Packages (Must be compiled first) ---
rtl/hash_sample_pkg.sv

# --- MAJOR SUBMODULES ---
lib/keccak-fips202-sv/rtl/*.sv
lib/poly-samplers/rtl/*.sv
lib/common_rtl/rtl/*.sv

# --- HASH SAMPLER UNIT TOP LEVEL MODULE ---
rtl/hash_sampler_unit.sv
