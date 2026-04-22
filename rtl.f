# --- MAJOR SUBMODULES ---
-f lib/common-rtl/rtl.f
-f lib/keccak-fips202-sv/rtl.f
-f lib/poly-samplers/rtl.f

# --- Packages ---
rtl/hash_sample_pkg.sv

# --- Packer ---
rtl/coeff_to_axis_packer.sv

# --- HASH SAMPLER UNIT TOP LEVEL ---
rtl/hash_sampler_unit.sv
