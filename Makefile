# 1. Import the central build system
include build-tools/common.mk

# =========================================================
# Test Vector Generation Logic
# =========================================================
VECTOR_JSON   := verif/test_vectors.json
VECTOR_SCRIPT := verif/generate_tb_files.py
VECTOR_STAMP  := verif/test_vectors/.generated_stamp

# This rule tells Make: "If the JSON or Script is newer than the stamp file, run this."
$(VECTOR_STAMP): $(VECTOR_JSON) $(VECTOR_SCRIPT)
	@echo "=== Regenerating Test Vectors from JSON ==="
	cd verif && python3 generate_tb_files.py
	@touch $(VECTOR_STAMP)

# =========================================================
# Hash Sampler Unit Override Target
# =========================================================
# Notice the dependency on $(VECTOR_STAMP) added here!
run_hash_sampler_unit_tb: build.f $(VECTOR_STAMP)
	@echo "=== Running hash_sampler_unit_tb with custom vector loop ($(SIM)) ==="
ifeq ($(SIM), verilator)
	@echo "Compiling Verilator binary once..."
	verilator $(VERILATOR_FLAGS) $(INCDIRS) --top-module hash_sampler_unit_tb -f build.f tb/hash_sampler_unit_tb.sv

	@# We use shell wildcard here so it evaluates AFTER the Python script creates the folders
	@for dir in verif/test_vectors/*/; do \
		test_name=$$(basename "$${dir%/}"); \
		echo ""; \
		echo "--- Running Verilator on $$test_name ---"; \
		./obj_dir/Vhash_sampler_unit_tb +TEST_DIR=$$dir 2>&1 | tee hash_sampler_unit_tb_$$test_name.log; \
	done
else
	@echo "Compiling ModelSim work library once..."
	vlib work
	vlog -work work -sv $(INCDIRS) -f build.f tb/hash_sampler_unit_tb.sv

	@# We use shell wildcard here so it evaluates AFTER the Python script creates the folders
	@for dir in verif/test_vectors/*/; do \
		test_name=$$(basename "$${dir%/}"); \
		echo ""; \
		echo "--- Running ModelSim on $$test_name ---"; \
		vsim -c -do "run -all; quit" work.hash_sampler_unit_tb +TEST_DIR=$$dir -l hash_sampler_unit_tb_$$test_name.log; \
	done
endif
